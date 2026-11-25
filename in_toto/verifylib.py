# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  verifylib.py

<Author>
  Lukas Puehringer <lukas.puehringer@nyu.edu>
  Santiago Torres-Arias <santiago@nyu.edu>

<Started>
  June 28, 2016

<Copyright>
  See LICENSE for licensing information.

<Purpose>

  Provides a library to verify an in-toto final product containing
  a software supply chain layout.

  Take a look at `in_toto_verify`'s docstring for more details about the
  entire verification workflow.

"""

import datetime
import fnmatch
import hashlib
import hmac
import json
import logging
import os

import iso8601
import securesystemslib.exceptions
import securesystemslib.formats
from dateutil import tz
from securesystemslib._gpg.exceptions import KeyExpirationError

import in_toto.formats
import in_toto.models.layout
import in_toto.models.link
import in_toto.rulelib
import in_toto.runlib
import in_toto.settings
from in_toto.exceptions import (
    BadReturnValueError,
    LayoutExpiredError,
    MaterialSetMismatchError,
    ReviewCutoffError,
    RuleVerificationError,
    SamplingVerificationError,
    SignatureVerificationError,
    ThresholdVerificationError,
)
from in_toto.formats import _check_parameter_dict, _check_public_keys
from in_toto.models.link import Link
from in_toto.models.metadata import Metadata

# Inherits from in_toto base logger (c.f. in_toto.log)
LOG = logging.getLogger(__name__)

RULE_TRACE = {}


def _raise_on_bad_retval(return_value, command=None):
    """
    <Purpose>
      Internal function that checks return values of shell commands, e.g. from
      inspections. Raises exception if the passed value is non-int and non-zero.

    <Arguments>
      return_value:
              The return value to be verified
      command: (optional)
              The command whose execution returned the value, used for exception
              message.

    <Exceptions>
      BadReturnValueError if the return_value is non-int and non-zero

    <Side Effects>
      None.

    <Returns>
      None.
    """

    msg = "Got non-{what} " + f"return value '{return_value}'"
    if command:  # noqa: SIM108
        msg = f"{msg} from command '{command}'."
    else:
        msg = f"{msg}."

    if not isinstance(return_value, int):
        raise BadReturnValueError(msg.format(what="int"))

    # TODO: in-toto specification suggests special behavior on
    # return_value == 127, but does not fully define that behavior yet

    if return_value != 0:
        raise BadReturnValueError(msg.format(what="zero"))


def load_links_for_layout(layout, link_dir_path):
    """
    <Purpose>
      Try to load all existing metadata files for each Step of the Layout
      from the current directory.

      For each step the metadata might consist of multiple (thresholds) Link
      or Layout (sub-layouts) files.

    <Arguments>
      layout:
            Layout object

      link_dir_path:
            A path to directory where links are loaded from


    <Side Effects>
      Calls function to read files from disk

    <Exceptions>
      in_toto.exceptions.LinkNotFoundError,
              if fewer than `threshold` link files can be found for any given
              step of the supply chain (preliminary threshold check)

    <Returns>
      A dictionary carrying all the found metadata corresponding to the
      passed layout, e.g.:

      {
        <step name> : {
          <functionary key id> : <Metadata containing a Link or Layout object>,
          ...
        }, ...
      }


    """
    steps_metadata = {}

    # Iterate over all the steps in the layout
    for step in layout.steps:
        links_per_step = {}

        # We try to load a link for every authorized functionary, but don't fail
        # if the file does not exist (authorized != required)
        # FIXME: Should we really pass on IOError, or just skip inexistent links?
        for authorized_keyid in step.pubkeys:
            # Iterate over the authorized key and if present over subkeys
            for keyid in [authorized_keyid] + list(
                layout.keys.get(authorized_keyid, {}).get("subkeys", {}).keys()
            ):
                filename = in_toto.models.link.FILENAME_FORMAT.format(
                    step_name=step.name, keyid=keyid
                )
                filepath = os.path.join(link_dir_path, filename)

                try:
                    metadata = Metadata.load(filepath)
                    links_per_step[keyid] = metadata

                except OSError:
                    pass

        # This is only a preliminary threshold check, based on (authorized)
        # filenames, to fail early. A more thorough signature-based threshold
        # check is indispensable.
        if len(links_per_step) < step.threshold:
            raise in_toto.exceptions.LinkNotFoundError(
                f"Step '{step.name}' requires '{step.threshold}'"
                f" link metadata file(s), found '{len(links_per_step)}'."
            )

        steps_metadata[step.name] = links_per_step

    return steps_metadata


def run_all_inspections(
    layout,
    persist_inspection_links,
    timeout=in_toto.settings.LINK_CMD_EXEC_TIMEOUT,
):
    """
    <Purpose>
      Extracts all inspections from a passed Layout's inspect field and
      iteratively runs each command defined in the Inspection's `run` field using
      `runlib.in_toto_run`, which returns a Link object.

      If a link command returns non-zero the verification is aborted.

    <Arguments>
      layout:
              A Layout object which is used to extract the Inspections.

      persist_inspection_links:
              A boolean indicating whether link metadata files for inspection
              are written to cwd.

      timeout:
              Integer that is the amount of seconds that the inspection run will
              fail after.

    <Exceptions>
      Calls function that raises BadReturnValueError if an inspection returned
      non-int or non-zero.

    <Returns>
      A dictionary of metadata about the executed inspections, e.g.:

      {
        <inspection name> : {
          <Link object>,
          ...
        }, ...
      }

    """
    inspection_links_dict = {}
    for inspection in layout.inspect:
        LOG.info("Executing command for inspection '%s'...", inspection.name)

        # FIXME: We don't want to use the base path for runlib so we patch this
        # for now. This will not stay!
        base_path_backup = in_toto.settings.ARTIFACT_BASE_PATH
        in_toto.settings.ARTIFACT_BASE_PATH = None

        # FIXME: What should we record as material/product?
        # Is the current directory a sensible default? In general?
        # If so, we should probably make it a default in run_link
        # We could use artifact rule paths.
        material_list = product_list = ["."]
        link = in_toto.runlib.in_toto_run(
            inspection.name,
            material_list,
            product_list,
            inspection.run,
            timeout=timeout,
        )

        _raise_on_bad_retval(
            link.signed.byproducts.get("return-value"), inspection.run
        )

        inspection_links_dict[inspection.name] = link.signed

        # If client requests persistent inspection links,
        # Dump the inspection link file for auditing
        # Keep in mind that this pollutes the verifier's (client's) filesystem.
        if persist_inspection_links:
            filename = in_toto.models.link.FILENAME_FORMAT_SHORT.format(
                step_name=inspection.name
            )
            link.dump(filename)

        in_toto.settings.ARTIFACT_BASE_PATH = base_path_backup

    return inspection_links_dict


def verify_layout_expiration(layout):
    """
    <Purpose>
      Raises an exception if the passed layout has expired, i.e. if its
      `expires` property is lesser "now".
      Time zone aware datetime objects in UTC+00:00 (Zulu Time) are used.

    <Arguments>
      layout:
              The Layout object to be verified.

    <Exceptions>
      LayoutExpiredError
      TBA (see https://github.com/in-toto/in-toto/issues/6)

    <Side Effects>
      None.

    """
    expire_datetime = iso8601.parse_date(layout.expires)
    if expire_datetime <= datetime.datetime.now(tz.tzutc()):
        raise LayoutExpiredError("Layout expired")


def substitute_parameters(layout, parameter_dictionary):
    """
    <Purpose>
      This function is a transitionary measure for parameter substitution (or
      any other solution defined by the in-toto team). As of now, it acts as
      a very simple replacement layer for python-like parameters

    <Arguments>
      layout:
              The Layout object to process.

        parameter_dictionary:
              A dictionary containing key-value pairs for substitution.

    <Exceptions>
      securesystemslib.exceptions.FormatError:
        if the parameter dictionary is malformed.

      KeyError:
        if one of the keys in the parameter dictionary are not present for
        substitution

    <Side Effects>
      The layout object will have any tags replaced with the corresponding
      values defined in the parameter dictionary.
    """
    _check_parameter_dict(parameter_dictionary)

    for step in layout.steps:
        new_material_rules = []
        for rule in step.expected_materials:
            new_rule = [
                stanza.format(**parameter_dictionary) for stanza in rule
            ]
            new_material_rules.append(new_rule)

        new_product_rules = []
        for rule in step.expected_products:
            new_rule = []
            for stanza in rule:
                new_rule.append(stanza.format(**parameter_dictionary))
            new_product_rules.append(new_rule)

        new_expected_command = [
            argv.format(**parameter_dictionary)
            for argv in step.expected_command
        ]

        step.expected_command = new_expected_command
        step.expected_materials = new_material_rules
        step.expected_products = new_product_rules

    for inspection in layout.inspect:
        new_material_rules = []
        for rule in inspection.expected_materials:
            new_rule = []
            for stanza in rule:
                new_rule.append(stanza.format(**parameter_dictionary))
            new_material_rules.append(new_rule)

        new_product_rules = []
        for rule in inspection.expected_products:
            new_rule = []
            for stanza in rule:
                new_rule.append(stanza.format(**parameter_dictionary))
            new_product_rules.append(new_rule)

        new_run = [
            argv.format(**parameter_dictionary) for argv in inspection.run
        ]

        inspection.run = new_run
        inspection.expected_materials = new_material_rules
        inspection.expected_products = new_product_rules


def verify_metadata_signatures(metadata, keys_dict):
    """
    <Purpose>
      Iteratively verifies the signatures of a Metadata object containing
      a Layout object for every verification key in the passed keys dictionary.

      Requires at least one key to be passed and requires every passed key to
      find a valid signature.

    <Arguments>
      metadata:
              A Metadata object containing a Layout whose signatures are
              verified.

      keys_dict:
              A dictionary of keys to verify the signatures.

    <Exceptions>
      securesystemslib.exceptions.FormatError
        if the passed key dict is invalid.

      SignatureVerificationError
        if an empty verification key dictionary was passed, or
        if any of the passed verification keys fails to verify a signature.

      securesystemslib._gpg.exceptions.KeyExpirationError:
        if any of the passed verification keys is an expired gpg key

    """
    _check_public_keys(keys_dict)

    # Fail if an empty verification key dictionary was passed
    if len(keys_dict) < 1:
        raise SignatureVerificationError(
            "Layout signature verification requires at least one key."
        )

    # Fail if any of the passed keys can't verify a signature on the Layout
    for verify_key in keys_dict.values():
        metadata.verify_signature(verify_key)


def verify_link_signature_thresholds(layout, steps_metadata):  # noqa: C901, PLR0912
    """
    <Purpose>
      Verify that for each step of the layout there are at least `threshold`
      links metadata, signed by different authorized functionaries and return the
      verified link metadata dictionary containing only authorized links metadata
      whose signatures were successfully verified.

      NOTE: If the layout's key store (`layout.keys`) lists a (master) key `K`,
      with a subkey `K'`, then `K'` is authorized implicitly, to sign any link
      that `K` is authorized to sign. In other words, the trust in a master key
      extends to the trust in a subkey. The inverse is not true.

    <Arguments>
      layout:
              A Layout object whose Steps are extracted and verified.

      steps_metadata:
              A dictionary containing link metadata per functionary per step,
              e.g.:
              {
                <link name> : {
                  <functionary key id> : <Metadata containing a Link or Layout
                                          object>,
                  ...
                }, ...
              }

    <Exceptions>
      ThresholdVerificationError
              If any of the steps of the passed layout does not have enough
              (`step.threshold`) links signed by different authorized
              functionaries.

    <Returns>
      A steps_metadata containing only links with valid signatures created by
      authorized functionaries.

    """
    # pylint: disable=too-many-locals

    # Create an inverse keys-subkeys dictionary, with subkey keyids as
    # dictionary keys and main keys as dictionary values. This will be
    # required below to assess main-subkey trust delegations.
    # We assume that a given subkey can only belong to one master key
    # TODO: Is this a safe assumption? Should we assert for it?
    main_keys_for_subkeys = {}
    for main_key in list(layout.keys.values()):
        for sub_keyid in main_key.get("subkeys", []):
            main_keys_for_subkeys[sub_keyid] = main_key

    # Dict for valid and authorized links of all steps of the layout
    verified_steps_metadata = {}

    # For each step of the layout check the signatures of corresponding links.
    # Consider only links where the signature is valid and keys are authorized,
    # and discard others.
    # Only count one of multiple links signed with different subkeys of a main
    # key towards link threshold.
    # Only proceed with final product verification if threshold requirements are
    # fulfilled.
    for step in layout.steps:
        # Dict for valid and authorized links of a given step
        verified_key_link_dict = {}
        # List of used keyids
        used_main_keyids = []

        # Do per step link threshold verification
        for link_keyid, link in steps_metadata.get(step.name, {}).items():
            # Iterate over authorized keyids to find a key or subkey corresponding
            # to the given link and check if the link's keyid is authorized.
            # Subkeys of authorized main keys are authorized implicitly.
            for authorized_keyid in step.pubkeys:
                authorized_key = layout.keys.get(authorized_keyid)
                main_key_for_subkey = main_keys_for_subkeys.get(
                    authorized_keyid
                )

                # The signing key is authorized ...
                if authorized_key and link_keyid == authorized_keyid:
                    verification_key = authorized_key
                    break

                # ... or the signing key is an authorized subkey ...
                if main_key_for_subkey and link_keyid == authorized_keyid:
                    verification_key = main_key_for_subkey
                    break

                # ... or the signing key is a subkey of an authorized key
                if authorized_key and link_keyid in authorized_key.get(
                    "subkeys", {}
                ):
                    verification_key = authorized_key
                    break

            else:
                LOG.info(
                    "Skipping link. Keyid '%s' is not authorized to sign links"
                    " for step '%s'",
                    link_keyid,
                    step.name,
                )
                continue

            # Verify signature and skip invalidly signed links
            try:
                link.verify_signature(verification_key)

            except SignatureVerificationError:
                LOG.info(
                    "Skipping link. Broken link signature with keyid '%s'"
                    " for step '%s'",
                    link_keyid,
                    step.name,
                )
                continue

            except KeyExpirationError as e:
                LOG.info("Skipping link. %s", e)
                continue

            # Warn if there are links signed by different subkeys of same main key
            if verification_key["keyid"] in used_main_keyids:
                LOG.warning(
                    "Found links signed by different subkeys of the same main"
                    " key '%s' for step '%s'. Only one of them is counted towards the"
                    " step threshold.",
                    verification_key["keyid"],
                    step.name,
                )

            used_main_keyids.append(verification_key["keyid"])

            # Keep only links with valid and authorized signature
            verified_key_link_dict[link_keyid] = link

        # For each step, verify that we have enough validly signed links from
        # distinct authorized functionaries. Links signed by different subkeys of
        # the same main key are counted only once towards the threshold.
        valid_authorized_links_cnt = len(set(used_main_keyids))
        # TODO: To guarantee that links are signed by different functionaries
        # we rely on the layout to not carry duplicate verification keys under
        # different dictionary keys, e.g. {keyid1: KEY1, keyid2: KEY1}
        # Maybe we should add such a check to the layout validation? Or here?
        if valid_authorized_links_cnt < step.threshold:
            raise ThresholdVerificationError(
                f"Step '{step.name}' requires at least '{step.threshold}' links"
                " validly signed by different authorized functionaries. Only"
                f" found '{valid_authorized_links_cnt}'"
            )

        # Add all good links of this step to the dictionary of links of all steps
        verified_steps_metadata[step.name] = verified_key_link_dict

    # Threshold verification succeeded, return valid and authorized links for
    # further verification
    return verified_steps_metadata


def verify_command_alignment(command, expected_command):
    """
    <Purpose>
      Checks if a run command aligns with an expected command. The commands align
      if all of their elements are equal. If alignment fails, a warning is
      printed.

      Note:
        Command alignment is a weak guarantee. Because a functionary can easily
        alias commands.

    <Arguments>
      command:
              A command list, e.g. ["vi", "foo.py"]
      expected_command:
              A command list, e.g. ["make", "install"]

    <Exceptions>
      None.

    <Side Effects>
      Logs warning in case commands do not align.

    """
    # In what case command alignment should fail and how that failure should be
    # propagated has been thoughly discussed in:
    # https://github.com/in-toto/in-toto/issues/46 and
    # https://github.com/in-toto/in-toto/pull/47
    # We chose the simplest solution for now, i.e. Warn if they do not align.
    if command != expected_command:
        LOG.warning(
            "Run command '%s' differs from expected command '%s'",
            command,
            expected_command,
        )


def verify_all_steps_command_alignment(layout, chain_link_dict):
    """
    <Purpose>
      Iteratively checks if all expected commands as defined in the
      Steps of a Layout align with the actual commands as recorded in the Link
      metadata.

    <Arguments>
      layout:
              A Layout object to extract the expected commands from.

      chain_link_dict:
              A dictionary containing link metadata per functionary per step,
              e.g.:
              {
                <link name> : {
                  <functionary key id> : <Link object>,
                  ...
                }, ...
              }

    <Exceptions>
      None.

    <Side Effects>
      None.

    """
    for step in layout.steps:
        # Find the according link for this step
        expected_command = step.expected_command
        key_link_dict = chain_link_dict[step.name]

        # FIXME: I think we could do this for one link per step only
        # providing that we verify command alignment AFTER threshold equality
        for keyid, link in key_link_dict.items():
            LOG.info(
                "Verifying command alignment for '%s'...",
                in_toto.models.link.FILENAME_FORMAT.format(
                    step_name=step.name, keyid=keyid
                ),
            )

            command = link.command
            verify_command_alignment(command, expected_command)


def verify_match_rule(rule_data, artifacts_queue, source_artifacts, links):
    """
    <Purpose>
      Filters artifacts from artifact queue using rule pattern and optional rule
      source prefix and consumes them if there is a corresponding destination
      artifact, filtered using the same rule pattern and an optional rule
      destination prefix, and source and destination artifacts have matching
      hashes.

      NOTE: The destination artifacts are extracted from the links dictionary,
      using destination name and destination type from the rule data. The source
      artifacts could also be extracted from the links dictionary, but would
      require the caller to pass source name and source type, as those are not
      encoded in the rule. However, we choose to let the caller directly pass the
      relevant artifacts.


    <Arguments>
      rule_data:
              An unpacked "MATCH" rule (see in_toto.rulelib).

      artifacts_queue:
              Not yet consumed artifacts (paths only).


      source_artifacts:
              All artifacts of the source item (including hashes).

      links:
              A dictionary containing link metadata per step or inspection, e.g.:
              {
                <link name> : <Link object>,
                ...
              }

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      The set of consumed artifacts (paths only).

    """
    consumed = set()

    # The rule can only consume artifacts if the destination link exists
    dest_link = links.get(rule_data["dest_name"])
    if not dest_link:
        return consumed

    # Extract destination artifacts from destination link
    dest_artifacts = getattr(dest_link, rule_data["dest_type"])

    # Filter part 1 - Filter artifacts using optional source prefix, and subtract
    # prefix before filtering with rule pattern (see filter part 2) to prevent
    # globbing in the prefix.
    if rule_data["source_prefix"]:
        # Add trailing slash to source prefix if it does not exist
        normalized_source_prefix = os.path.join(
            rule_data["source_prefix"], ""
        ).replace("\\", "/")

        filtered_source_paths = [
            artifact_path[len(normalized_source_prefix) :]
            for artifact_path in artifacts_queue
            if artifact_path.startswith(normalized_source_prefix)
        ]

    else:
        filtered_source_paths = artifacts_queue

    # Filter part 2 - glob above filtered artifact paths
    filtered_source_paths = fnmatch.filter(
        filtered_source_paths, rule_data["pattern"]
    )

    # Iterate over filtered source paths and try to match the corresponding
    # source artifact hash with the corresponding destination artifact hash
    for path in filtered_source_paths:
        # If a source prefix was specified, we subtracted the prefix above before
        # globbing. We have to re-prepend the prefix in order to retrieve the
        # corresponding source artifact below.
        if rule_data["source_prefix"]:
            full_source_path = os.path.join(
                rule_data["source_prefix"], path
            ).replace("\\", "/")

        else:
            full_source_path = path

        # If a destination prefix was specified, the destination artifact should
        # be queried with the full destination path, i.e. the prefix joined with
        # the globbed path.
        if rule_data["dest_prefix"]:
            full_dest_path = os.path.join(
                rule_data["dest_prefix"], path
            ).replace("\\", "/")

        else:
            full_dest_path = path

        # Extract source artifact hash dict
        # We know the source artifact is available, it is also in the queue
        source_artifact = source_artifacts[full_source_path]

        # Don't consume source artifact w/o corresponding dest artifact (by path)
        try:
            dest_artifact = dest_artifacts[full_dest_path]
        except KeyError:
            continue

        # Don't consume source artifact w/o corresponding dest artifact (by hash)
        if source_artifact != dest_artifact:
            continue

        # Source and destination matched, consume artifact
        consumed.add(full_source_path)

    return consumed


def verify_create_rule(rule_pattern, artifacts_queue, materials, products):
    """
    <Purpose>
      Filters artifacts from artifacts queue using rule pattern and consumes them
      if they are not in the materials set but are in the products set, i.e.
      were created.

    <Arguments>
      rule_pattern:
              A "CREATE" rule pattern (see in_toto.rulelib).

      artifacts_queue:
              Not yet consumed artifacts (paths only).

      materials:
              All materials of an item (paths only).

      products:
              All products of an item (paths only).

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      The set of consumed artifacts (paths only).

    """
    # Filter queued artifacts using the rule pattern
    filtered_artifacts = fnmatch.filter(artifacts_queue, rule_pattern)

    # Consume filtered artifacts that are products but not materials
    return set(filtered_artifacts) & (products - materials)


def verify_delete_rule(rule_pattern, artifacts_queue, materials, products):
    """
    <Purpose>
      Filters artifacts from artifacts queue using rule pattern and consumes them
      if they are in the materials set but are not in the products set, i.e.
      were deleted.

    <Arguments>
      rule_pattern:
              A "DELETE" rule pattern (see in_toto.rulelib).

      artifacts_queue:
              Not yet consumed artifacts (paths only).

      materials:
              All materials of an item (paths only).

      products:
              All products of an item (paths only).

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      The set of consumed artifacts (paths only).

    """
    # Filter queued artifacts using the rule pattern
    filtered_artifacts = fnmatch.filter(artifacts_queue, rule_pattern)

    # Consume filtered artifacts that are materials but not products
    return set(filtered_artifacts) & (materials - products)


def verify_modify_rule(rule_pattern, artifacts_queue, materials, products):
    """
    <Purpose>
      Filters artifacts from artifacts queue using rule pattern and consumes them
      if they are in both the materials dict and in the products doct, but have
      different hashes, i.e. were modified.

    <Arguments>
      rule_pattern:
              A "MODIFY" rule pattern (see in_toto.rulelib).

      artifacts_queue:
              Not yet consumed artifacts (paths only).

      materials:
              All materials of an item (including hashes).

      products:
              All products of an item (including hashes).

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      The set of consumed artifacts (paths only).

    """
    # Filter queued artifacts using the rule pattern
    filtered_artifacts = fnmatch.filter(artifacts_queue, rule_pattern)

    # Filter filtered artifacts that are materials and products
    filtered_artifacts = (
        set(filtered_artifacts) & set(materials.keys()) & set(products.keys())
    )

    # Consume filtered artifacts that have different hashes
    consumed = set()
    for path in filtered_artifacts:
        if materials[path] != products[path]:
            consumed.add(path)

    return consumed


def verify_allow_rule(rule_pattern, artifacts_queue):
    """
    <Purpose>
      Consumes artifacts, filtered from the artifacts queue using rule pattern.

    <Arguments>
      rule_pattern:
              An "ALLOW" rule pattern (see in_toto.rulelib).

      artifacts_queue:
              Not yet consumed artifacts (paths only).

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      The set of consumed artifacts (paths only).

    """
    # Filter queued artifacts using the rule pattern
    filtered_artifacts = fnmatch.filter(artifacts_queue, rule_pattern)

    # Consume all filtered artifacts
    return set(filtered_artifacts)


def verify_disallow_rule(rule_pattern, artifacts_queue):
    """
    <Purpose>
      Raises RuleVerificationError if rule pattern applies to any artifacts in
      the queue.

      NOTE: Each set of rules should have a terminal DISALLOW rule to make
      overall verification fail in case preceding rules did not consume all
      artifacts as intended.

    <Arguments>
      rule_pattern:
              A "DISALLOW" rule pattern (see in_toto.rulelib).

      artifacts_queue:
              Not yet consumed artifacts (paths only).

    <Exceptions>
      RuleVerificationError
          if the rule pattern filters artifacts in the artifact queue.

    <Side Effects>
      None.

    <Returns>
      None.

    """
    filtered_artifacts = fnmatch.filter(artifacts_queue, rule_pattern)

    if filtered_artifacts:
        raise RuleVerificationError(
            f"'DISALLOW {rule_pattern}' matched the following artifacts: {filtered_artifacts}\n{_get_artifact_rule_traceback()}"
        )


def verify_require_rule(filename, artifacts_queue):
    """
    <Purpose>
      Raises RuleVerificationError if the filename provided does not exist in the
      artifacts_queue

    <Arguments>
      filename:
              A single filename (see issues #193 and #152). We will ignore the
              artifact rule pattern because it's ambiguous and instead treat it
              as a literal file name.

      artifacts_queue:
              Not yet consumed artifacts (paths only).

    <Exceptions>
      RuleVerificationError:
        if the filename is not present in the artifacts queue

    <Side Effects>
      None.

    <Returns>
      None.

    """
    if filename not in artifacts_queue:
        raise RuleVerificationError(
            f"'REQUIRE {filename}' did not find {filename} "
            f"in: {artifacts_queue}\n{_get_artifact_rule_traceback()}"
        )


def _get_artifact_rule_traceback():
    """Build and return string form global `RULE_TRACE` which may be used as
    error message for RuleVerificationError.

    """
    traceback_str = "Full trace for 'expected_{}' of item '{}':\n".format(
        RULE_TRACE["source_type"], RULE_TRACE["source_name"]
    )

    # Show all materials and products available in the beginning and
    # label the one that is used to generate a queue.
    for source_type in ["materials", "products"]:
        traceback_str += "Available {}{}:\n{}\n".format(
            source_type,
            [" (used for queue)", ""][RULE_TRACE["source_type"] != source_type],
            RULE_TRACE[source_type],
        )

    for trace_entry in RULE_TRACE["trace"]:
        traceback_str += "Queue after '{}':\n".format(
            " ".join(trace_entry["rule"])
        )
        traceback_str += "{}\n".format(trace_entry["queue"])

    return traceback_str


def verify_item_rules(source_name, source_type, rules, links):
    """
    <Purpose>
      Apply all passed material or product rules (see source_type) of a given
      step or inspection (see source_name), to enforce and authorize the
      corresponding artifacts and to guarantee that artifacts are linked together
      across steps of the supply chain.

      The mode of operation is similar to that of a firewall:
      In the beginning all materials or products of the step or inspection are
      placed into an artifact queue. The rules are then applied sequentially,
      consuming artifacts in the queue, i.e. removing them from the queue upon
      successful application.

      The consumption of artifacts by itself has no effects on the verification.
      Only through a subsequent "DISALLOW" rule, that finds unconsumed artifacts,
      is an exception raised. Similarly does the "REQUIRE" rule raise exception,
      if it does not find the artifact it requires, because it has falsely been
      consumed or was not there from the beginning.



    <Arguments>
      source_name:
              The name of the item (step or inspection) being verified.

      source_type:
              One of "materials" or "products" depending on whether the rules are
              taken from the "expected_materials" or "expected_products" field of
              the item being verified.

      rules:
              The list of rules (material or product rules) for the item being
              verified.

      links:
              A dictionary containing link metadata per step or inspection, e.g.:
              {
                <link name> : <Link object>,
                ...
              }

    <Exceptions>
      FormatError
          if source_type is not "materials" or "products", or
          if a rule in the passed list of rules does not conform with any rule
          format.

      RuleVerificationError
          if a DISALLOW rule matches disallowed artifacts, or
          if a REQUIRE rule does not find a required artifact.

    <Side Effects>
      Clears and populates the global RULE_TRACE data structure.

    """
    if source_type not in {"materials", "products"}:
        raise securesystemslib.exceptions.FormatError(
            "Argument 'source_type' of function 'verify_item_rules' has to be "
            f"one of 'materials' or 'products'. Got: '{source_type}'"
        )

    # Create shortcuts to item's materials and products (including hashes),
    # required to verify "modify" and "match" rules.
    materials_dict = links[source_name].materials
    products_dict = links[source_name].products

    # All other rules only require materials or products paths (without hashes)
    materials_paths = set(materials_dict.keys())
    products_paths = set(products_dict.keys())

    # Depending on the source type we create the artifact queue from the item's
    # materials or products and use it to keep track of (not) consumed artifacts.
    # The queue also only contains artifact keys (without hashes)
    artifacts = getattr(links[source_name], source_type)
    artifacts_queue = set(artifacts.keys())

    # Reset and re-populate rule traceback info dict for a rich error message
    RULE_TRACE.clear()
    RULE_TRACE["source_name"] = source_name
    RULE_TRACE["source_type"] = source_type
    RULE_TRACE["materials"] = list(materials_dict)
    RULE_TRACE["products"] = list(products_dict)
    RULE_TRACE["trace"] = []

    # Process rules and remove consumed items from queue in each iteration
    for rule in rules:
        LOG.info("Verifying '%s'...", " ".join(rule))

        # Parse the rule and create two shortcuts to contained rule data
        rule_data = in_toto.rulelib.unpack_rule(rule)
        _type = rule_data["rule_type"]
        pattern = rule_data["pattern"]

        # Initialize empty consumed set as fallback for rules that do not consume
        # artifacts. All rules except "disallow" and "require" consume artifacts.
        consumed = set()

        if _type == "match":
            consumed = verify_match_rule(
                rule_data, artifacts_queue, artifacts, links
            )

        elif _type == "create":
            consumed = verify_create_rule(
                pattern, artifacts_queue, materials_paths, products_paths
            )

        elif _type == "delete":
            consumed = verify_delete_rule(
                pattern, artifacts_queue, materials_paths, products_paths
            )

        elif _type == "modify":
            consumed = verify_modify_rule(
                pattern, artifacts_queue, materials_dict, products_dict
            )

        elif _type == "allow":
            consumed = verify_allow_rule(pattern, artifacts_queue)

        # It's up to the "disallow" and "require" rule to raise an error if
        # artifacts were not consumed as intended
        elif _type == "disallow":
            verify_disallow_rule(pattern, artifacts_queue)

        elif _type == "require":
            verify_require_rule(pattern, artifacts_queue)

        else:  # pragma: no cover (unreachable)
            raise securesystemslib.exceptions.FormatError(
                f"Invaldid rule type '{_type}'."
            )

        artifacts_queue -= consumed

        # Append rule and copy of queue to global info for a rich error message
        RULE_TRACE["trace"].append(
            {"rule": rule, "queue": list(artifacts_queue)}
        )


def verify_all_item_rules(items, links):
    """
    <Purpose>
      Iteratively verifies artifact rules of passed items (Steps or Inspections).

    <Arguments>
      items:
              A list containing Step or Inspection objects whose material
              and product rules will be verified.

      links:
              A dictionary containing link metadata per step or inspection, e.g.:
              {
                <link name> : <Link object>,
                ...
              }

    <Exceptions>
      None.

    <Side Effects>
      None.

    """
    for item in items:
        LOG.info("Verifying material rules for '%s'...", item.name)
        verify_item_rules(
            item.name, "materials", item.expected_materials, links
        )

        LOG.info("Verifying product rules for '%s'...", item.name)
        verify_item_rules(item.name, "products", item.expected_products, links)


def verify_threshold_constraints(layout, chain_link_dict):
    """
    <Purpose>
      Verifies that all links corresponding to a given step report the same
      materials and products.

      NOTE: This function does not verify if the signatures of each link
      corresponding to a step are valid or created by a different authorized
      functionary. This should be done earlier, using the function
      `verify_link_signature_thresholds`.

    <Arguments>
      layout:
              The layout whose step thresholds are being verified

      chain_link_dict:
              A dictionary containing link metadata per functionary per step,
              e.g.:
              {
                <link name> : {
                  <functionary key id> : <Link object>,
                  ...
                }, ...
              }

    <Exceptions>
      ThresholdVerificationError
          If there are not enough (threshold) links for a steps

          If the artifacts for all links of a step are not equal


    <Side Effects>
      None.

    """

    # We are only interested in links that are related to steps defined in the
    # Layout, so iterate over layout.steps
    for step in layout.steps:
        # Skip steps that don't require multiple functionaries
        if step.threshold <= 1:
            LOG.info(
                "Skipping threshold verification for step '%s' with"
                " threshold '%s'...",
                step.name,
                step.threshold,
            )
            continue

        LOG.info(
            "Verifying threshold for step '%s' with threshold '%s'...",
            step.name,
            step.threshold,
        )
        # Extract the key_link_dict for this step from the passed chain_link_dict
        key_link_dict = chain_link_dict[step.name]

        # Check if we have at least <threshold> links for this step
        # NOTE: This is already done in `verify_link_signature_thresholds`,
        # Should we remove the check?
        if len(key_link_dict) < step.threshold:
            raise ThresholdVerificationError(
                f"Step '{step.name}' not performed by enough functionaries!"
            )

        # Take a reference link (e.g. the first in the step_link_dict)
        reference_keyid = next(iter(key_link_dict.keys()))
        reference_link = key_link_dict[reference_keyid]

        # Iterate over all links to compare their properties with a reference_link
        for keyid, link in key_link_dict.items():
            # TODO: Do we only care for artifacts, or do we want to
            # assert equality of other properties as well?
            if (
                reference_link.materials != link.materials
                or reference_link.products != link.products
            ):
                raise ThresholdVerificationError(
                    "Links '{}' and '{}' have different artifacts!".format(
                        in_toto.models.link.FILENAME_FORMAT.format(
                            step_name=step.name, keyid=reference_keyid
                        ),
                        in_toto.models.link.FILENAME_FORMAT.format(
                            step_name=step.name, keyid=keyid
                        ),
                    )
                )


def reduce_chain_links(chain_link_dict):
    """
    <Purpose>
      Iterates through the passed chain_link_dict and builds a dict with
      step-name as keys and link objects as values.
      We already check if the links of different functionaries are
      identical.

    <Arguments>
      layout:
              The layout specified by the project owner against which the
              threshold will be verified.

      chain_link_dict:
              A dictionary containing link metadata per functionary per step,
              e.g.:
              {
                <link name> : {
                  <functionary key id> : <Link object>,
                  ...
                }, ...
              }

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      A dictionary containing one Link metadata object per step only if
      the link artifacts of all link objects are identical for a step.

    """

    reduced_chain_link_dict = {}

    for step_name, key_link_dict in chain_link_dict.items():
        # Extract the key_link_dict for this step from the passed chain_link_dict
        # take one exemplary link (e.g. the first in the step_link_dict)
        # form the reduced_chain_link_dict to return
        reduced_chain_link_dict[step_name] = next(iter(key_link_dict.values()))

    return reduced_chain_link_dict


def verify_sublayouts(
    layout, steps_metadata, superlayout_link_dir_path, inspect_timeout
):
    """
    <Purpose>
      Extracts link or layout object for each step in steps_metadata. Checks if
      any step has been delegated by the functionary, recurses into the
      delegation, and replaces the layout object with an equivalent link object.
      Returns the extracted link objects in a dict called chain_link_dict.

    <Arguments>
      layout:
              The layout specified by the project owner.

      steps_metadata:
              A dictionary containing link metadata per functionary per step,
              e.g.:
              {
                <link name> : {
                  <functionary key id> : <Metadata containing a Link or Layout
                                            object>,
                  ...
                }, ...
              }

      superlayout_link_dir_path:
              A path to a directory, where links of the superlayout are loaded
              from. Links of the sublayout are expected to be in a subdirectory
              relative to this path, with a name in the format
              in_toto.models.layout.SUBLAYOUT_LINK_DIR_FORMAT.

      inspect_timeout:
              Integer value that is the number of seconds to pass to the run
              command to timeout the subprocess within.

    <Exceptions>
      raises an Exception if verification of the delegated step fails.

    <Side Effects>
      None.

    <Returns>
      The passed dictionary containing Link objects instead of metadata per
      functionary per step, with layouts replaced with summary links.
      e.g.:
      {
        <link name> : {
          <functionary key id> : <Link object>,
          ...
        }, ...
      }

    """
    chain_link_dict = {}

    for step_name, metadata_dict in steps_metadata.items():
        key_link_dict = {}
        for keyid, metadata in metadata_dict.items():
            payload = metadata.get_payload()

            if payload.type_ == "layout":
                LOG.info("Verifying sublayout %s...", step_name)
                layout_key_dict = {}

                # Retrieve the entire key object for the keyid
                # corresponding to the link
                layout_key_dict = {keyid: layout.keys.get(keyid)}

                # Sublayout links are expected to be in a directory with the following
                # name relative the the current link directory path, i.e. if there
                # are multiple levels of sublayout nesting, the links are expected to
                # be nested accordingly
                sub_link_dir = (
                    in_toto.models.layout.SUBLAYOUT_LINK_DIR_FORMAT.format(
                        name=step_name, keyid=keyid
                    )
                )

                sublayout_link_dir_path = os.path.join(
                    superlayout_link_dir_path, sub_link_dir
                )

                # Make a recursive call to in_toto_verify with the
                # layout and the extracted key object
                summary_link = in_toto_verify(
                    metadata,
                    layout_key_dict,
                    link_dir_path=sublayout_link_dir_path,
                    step_name=step_name,
                    inspect_timeout=inspect_timeout,
                )

                # Replace the layout object with the link object returned
                # by in-toto-verify
                payload = summary_link

            key_link_dict[keyid] = payload
        chain_link_dict[step_name] = key_link_dict

    return chain_link_dict


def get_summary_link(layout, reduced_chain_link_dict, name):
    """
    <Purpose>
      Merges the materials of the first step (as mentioned in the layout)
      and the products of the last step and returns a new link.
      This link reports the materials and products and summarizes the
      overall software supply chain.
      NOTE: The assumption is that the steps mentioned in the layout are
      to be performed sequentially. So, the first step mentioned in the
      layout denotes what comes into the supply chain and the last step
      denotes what goes out.

    <Arguments>
      layout:
              The layout specified by the project owner.

      reduced_chain_link_dict:
              A dictionary containing link metadata per step,
              e.g.:
              {
                <link name> : <Link object>,
                ...
              }
      name:
              The name that the summary link will be associated with.

    <Exceptions>
      None.

    <Side Effects>
      None.

    <Returns>
      A Link object which summarizes the materials and products of the overall
      software supply chain.

    """
    # Create empty link object
    summary_link = in_toto.models.link.Link()

    # Take first and last link in the order the corresponding
    # steps appear in the layout, if there are any.
    if len(layout.steps) > 0:
        first_step_link = reduced_chain_link_dict[layout.steps[0].name]
        last_step_link = reduced_chain_link_dict[layout.steps[-1].name]

        summary_link.materials = first_step_link.materials
        summary_link.name = name

        summary_link.products = last_step_link.products
        summary_link.byproducts = last_step_link.byproducts
        summary_link.command = last_step_link.command

    return summary_link


def in_toto_verify(  # noqa: PLR0913, PLR0917, RUF100
    metadata,
    layout_key_dict,
    link_dir_path=".",
    substitution_parameters=None,
    step_name="",
    persist_inspection_links=True,
    inspect_timeout=in_toto.settings.LINK_CMD_EXEC_TIMEOUT,
):
    """Performs complete in-toto supply chain verification for a final product.

    The verification procedure consists of the following activities, performed in
    the given order:

    1.  Verify layout signatures
    2.  Verify layout expiration date
    3.  Substitute placeholders in the layout
    4.  Load link metadata
    5.  Verify link signatures with keys in layout
    6.  Recurse into sublayout verification
    7.  Soft-verify alignment of reported and expected commands. Note:
        verification does not fail if commands don't match, instead a warning is
        logged as per the in-toto specification --
        https://github.com/in-toto/docs/blob/master/in-toto-spec.md#431-steps
    8.  Verify threshold artifact constraints
    9.  Process step product and material rules
    10. Execute inspection commands and generate inspection links
    11. Process inspection product and material rules

    Note: in-toto's verification workflow directly uses the key for verifying
    signatures. It does not communicate with external sources of information for
    specific attributes about keys. This ensures that verification can be
    performed in isolation. It is the supply chain owner's responsibility to
    consider such attributes before using the key to sign the layout or adding
    it to the layout. For example, in-toto does not rely on the creation time,
    revocation status, and usage flags for PGP keys. To revoke or otherwise
    affect the usage of a key, the supply chain owner must sign a new layout
    with the corresponding changes.

    Arguments:
      metadata: A Metadata object that contains a Layout object to be verified.

      layout_key_dict: A public key dictionary. The verification routine requires
          at least one key, and a valid signature on the layout for each key.

      link_dir_path (optional): A directory path to link metadata files. The
          expected filename format for link metadata files is
          ``STEP-NAME.KEYID-PREFIX.link``. Link metadata files for a sublayout
          are loaded from a subdirectory relative to the link_dir_path of the
          superlayout. The expected directory name format is
          ``SUBLAYOUT-STEP-NAME.KEYID-PREFIX``.

      substitution_parameters (optional): A dictionary with substitution values
          for artifact rules (steps and inspections), the expected command
          attribute (steps), and the run attribute (inspections) in the layout.

      step_name (optional): A name assigned to the returned link. This is mostly
          useful during recursive sublayout verification.

      persist_inspection_links (optional): A boolean that determines whether or
          not link metadata files for inspection are written to cwd.

      inspect_timeout (optional): An integer value that defaults to
          in_toto.settings.LINK_CMD_EXEC_TIMEOUT in seconds which ends up timing
          out the run command subprocess if it runs over.

    Raises:
      securesystemslib.exceptions.FormatError: Passed parameters are malformed.

      SignatureVerificationError: No layout verification key is passed, or any of
          the passed keys fails to verify a signature.

      LayoutExpiredError: The layout is expired.

      LinkNotFoundError: Fewer than threshold link metadata files can be found
          for a step of the layout.

      ThresholdVerificationError: Fewer than threshold links, validly signed by
          different authorized functionaries, who agree on the recorded materials
          and products, can be found for a step of the layout. (Links with
          invalid signatures or signatures by unauthorized functionaries are
          ignored.)

      RuleVerificationError: A DISALLOW rule matches disallowed artifacts, or
          a REQUIRE rule does not find a required artifact.

      BadReturnValueError: An inspection command returns a non-zero value.

    Side Effects:
      Reads link metadata files from disk.
      Runs inspection commands in subprocess.

    Returns:
      A Link object, which summarizes the materials and products of the overall
      software supply chain. This is mostly useful during recursive sublayout
      verification.

    """

    LOG.info("Verifying layout metadata signatures...")
    verify_metadata_signatures(metadata, layout_key_dict)

    # For the rest of the verification we only care about the layout payload
    # (Layout) that carries all the information and not about the layout
    # container (Metablock) that also carries the signatures
    LOG.info("Extracting layout from metadata...")
    layout = metadata.get_payload()

    LOG.info("Verifying layout expiration...")
    verify_layout_expiration(layout)

    # If there are parameters sent to the translation layer, substitute them
    if substitution_parameters is not None:
        LOG.info("Performing parameter substitution...")
        substitute_parameters(layout, substitution_parameters)

    LOG.info("Reading link metadata files...")
    steps_metadata = load_links_for_layout(layout, link_dir_path)

    LOG.info("Verifying link metadata signatures...")
    steps_metadata = verify_link_signature_thresholds(layout, steps_metadata)

    LOG.info("Verifying sublayouts...")
    chain_link_dict = verify_sublayouts(
        layout, steps_metadata, link_dir_path, inspect_timeout
    )

    LOG.info("Verifying alignment of reported commands...")
    verify_all_steps_command_alignment(layout, chain_link_dict)

    LOG.info("Verifying threshold constraints...")
    verify_threshold_constraints(layout, chain_link_dict)
    reduced_chain_link_dict = reduce_chain_links(chain_link_dict)

    # NOTE: Processing step rules before executing inspections guarantees that
    # inspection commands don't run on compromised target files, however, this
    # also precludes step match rules from referencing inspection artifacts.
    LOG.info("Verifying Step rules...")
    verify_all_item_rules(layout.steps, reduced_chain_link_dict)

    LOG.info("Executing Inspection commands...")
    inspection_link_dict = run_all_inspections(
        layout, persist_inspection_links, inspect_timeout
    )

    LOG.info("Verifying Inspection rules...")
    # Artifact rules for inspections can reference links that correspond to
    # Steps or Inspections, hence the concatenation of both collections of links
    combined_links = reduced_chain_link_dict.copy()
    combined_links.update(inspection_link_dict)
    verify_all_item_rules(layout.inspect, combined_links)

    # We made it this far without exception that means, verification passed
    LOG.info("The software product passed all verification.")

    # Return a link file which summarizes the entire software supply chain
    # This is mostly relevant if the currently verified supply chain is embedded
    # in another supply chain
    return get_summary_link(layout, reduced_chain_link_dict, step_name)


SAMPLING_PROTOCOL_VERSION = "in-toto-batch-review/v1"
SAMPLING_ALGORITHM = "hmac-sha256-rank-v1"
FIXED_BATCH_SEED = "in-toto-fixed-batch-seed/v1"
DEFAULT_BATCH_SEED = FIXED_BATCH_SEED
DEFAULT_SAMPLE_SIZE = 2


class _AttributeDict(dict):
    """Dictionary with read/write attribute access for known fields."""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def __setattr__(self, name, value):
        self[name] = value


class SamplingPolicy(_AttributeDict):
    """Fixed ex-ante batch sampling agreement."""

    def __init__(self, seed=None, sample_size=None, cutoff=None, **kwargs):
        data = {}
        if isinstance(seed, dict):
            data.update(seed)
            if sample_size is not None:
                data.setdefault("sample_size", sample_size)
            if cutoff is not None:
                data.setdefault("cutoff", cutoff)
        else:
            data.update(kwargs)
            if seed is not None:
                data["seed"] = seed
            if sample_size is not None:
                data["sample_size"] = sample_size
            if cutoff is not None:
                data["cutoff"] = cutoff

        if data.get("sample_size") is None:
            data["sample_size"] = data.pop("size", DEFAULT_SAMPLE_SIZE)
        data.setdefault("seed", FIXED_BATCH_SEED)
        if data.get("cutoff") is None:
            data["cutoff"] = data.pop(
                "release_cutoff", data.pop("deadline", None)
            )
        data.setdefault("threshold", 1)
        data.setdefault("artifact_type", "materials")
        data.setdefault("reviewers", [])
        data.setdefault("algorithm", SAMPLING_ALGORITHM)
        super().__init__(data)
        self.validate()

    @classmethod
    def read(cls, source):
        if isinstance(source, cls):
            return source
        if isinstance(source, dict):
            return cls(**source)
        if isinstance(source, (str, os.PathLike)):
            with open(source, encoding="utf-8") as handle:
                return cls(**json.load(handle))
        raise securesystemslib.exceptions.FormatError(
            "Sampling policy must be a dictionary or JSON path"
        )

    @classmethod
    def from_dict(cls, data):
        return cls.read(data)

    def validate(self):
        if not isinstance(self.get("seed"), str) or not self["seed"]:
            raise securesystemslib.exceptions.FormatError(
                "Sampling policy seed must be a non-empty string"
            )
        size = self.get("sample_size")
        if not isinstance(size, int) or isinstance(size, bool) or size < 1:
            raise securesystemslib.exceptions.FormatError(
                "Sampling policy sample_size must be a positive integer"
            )
        if self.get("cutoff") is not None:
            parse_review_timestamp(self["cutoff"], "cutoff")
        threshold = self.get("threshold")
        if (
            not isinstance(threshold, int)
            or isinstance(threshold, bool)
            or threshold < 1
        ):
            raise securesystemslib.exceptions.FormatError(
                "Sampling policy threshold must be a positive integer"
            )

    @property
    def digest(self):
        return hashlib.sha256(
            _canonical_json(dict(sorted(self.items())))
        ).hexdigest()


class SamplingDraw(_AttributeDict):
    """Recomputable deterministic draw sheet."""

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict):
            raise securesystemslib.exceptions.FormatError(
                "Draw sheet must be a dictionary"
            )
        return cls(data)

    @classmethod
    def read(cls, source):
        if isinstance(source, cls):
            return source
        if isinstance(source, dict):
            return cls.from_dict(source)
        if isinstance(source, (str, os.PathLike)):
            with open(source, encoding="utf-8") as handle:
                return cls.from_dict(json.load(handle))
        raise securesystemslib.exceptions.FormatError(
            "Draw sheet must be a dictionary or JSON path"
        )

    @classmethod
    def load(cls, path):
        return cls.read(path)

    def dump(self, path):
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(self.to_dict(), handle, indent=2, sort_keys=True)
            handle.write("\n")

    def to_dict(self):
        return dict(self)


DrawSheet = SamplingDraw
SampleDraw = SamplingDraw


class SamplingResult(_AttributeDict):
    """Result of a batch sampling review, including late evidence."""

    @property
    def passed(self):
        return bool(self.get("passed", self.get("valid", False)))

    @property
    def valid(self):
        return self.passed

    @property
    def ok(self):
        return self.passed

    def __bool__(self):
        return self.passed

    def raise_for_status(self):
        if self.passed:
            return self
        result = self
        if result.get("changes") or result.get("full_set_changed"):
            raise MaterialSetMismatchError(
                "Signed material full set does not match the batch draw",
                result=result,
            )
        if result.get("late") and not result.get("accepted"):
            raise ReviewCutoffError(
                "All review confirmations are late for the release cutoff",
                result=result,
            )
        raise SamplingVerificationError(
            "Sampling review verification failed", result=result
        )

    def dump(self, path):
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(dict(self), handle, indent=2, sort_keys=True)
            handle.write("\n")


def _canonical_json(data):
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def parse_review_timestamp(value, field="timestamp"):
    """Parse an ISO 8601 timestamp and return UTC-aware datetime."""
    if isinstance(value, datetime.datetime):
        parsed = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        parsed = datetime.datetime.fromtimestamp(value, tz=tz.tzutc())
    elif isinstance(value, str):
        try:
            parsed = iso8601.parse_date(value)
        except iso8601.ParseError as exc:
            raise securesystemslib.exceptions.FormatError(
                f"Malformed ISO 8601 timestamp in {field!r}: {value!r}"
            ) from exc
    else:
        raise securesystemslib.exceptions.FormatError(
            f"{field} must be an ISO 8601 string or datetime"
        )

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=tz.tzutc())
    return parsed.astimezone(tz.tzutc())


def _isoformat(value):
    return parse_review_timestamp(value).isoformat().replace("+00:00", "Z")


def verify_review_time(
    reviewed_at=None,
    cutoff=None,
    *,
    review_time=None,
    timestamp=None,
    deadline=None,
    release_cutoff=None,
    raise_on_late=True,
    **_kwargs,
):
    """Check whether a confirmation is at or before the review cutoff."""
    reviewed_at = reviewed_at or review_time or timestamp
    cutoff = cutoff or deadline or release_cutoff
    if reviewed_at is None or cutoff is None:
        raise securesystemslib.exceptions.FormatError(
            "Both reviewed_at and cutoff are required"
        )

    reviewed_dt = parse_review_timestamp(reviewed_at, "reviewed_at")
    cutoff_dt = parse_review_timestamp(cutoff, "cutoff")
    on_time = reviewed_dt <= cutoff_dt
    verification = SamplingResult(
        passed=on_time,
        valid=on_time,
        on_time=on_time,
        late=not on_time,
        status="on-time" if on_time else "late",
        reviewed_at=_isoformat(reviewed_dt),
        cutoff=_isoformat(cutoff_dt),
    )
    if not on_time and raise_on_late:
        raise ReviewCutoffError(
            "Review confirmation arrived after the release cutoff",
            result=verification,
        )
    return verification


check_review_time = verify_review_time
verify_review_timestamp = verify_review_time
verify_review_cutoff = verify_review_time


def is_review_on_time(reviewed_at, cutoff):
    return bool(
        verify_review_time(reviewed_at, cutoff, raise_on_late=False).on_time
    )


def _normalize_hashes(hashes):
    """Normalize an in-toto hash dictionary or bare SHA-256 hex string."""
    if isinstance(hashes, str):
        return {"sha256": hashes.strip().lower()}
    if not isinstance(hashes, dict):
        raise securesystemslib.exceptions.FormatError(
            "Artifact hashes must be a string or dictionary"
        )

    normalized = {}
    for algorithm, digest in hashes.items():
        if not isinstance(algorithm, str) or not isinstance(digest, str):
            raise securesystemslib.exceptions.FormatError(
                "Artifact hash algorithms and digests must be strings"
            )
        normalized[algorithm.lower()] = digest.strip().lower()
    return dict(sorted(normalized.items()))


def _hash_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"sha256": digest.hexdigest()}


def _artifact_name(path, base_dir=None):
    if base_dir:
        return os.path.relpath(path, base_dir).replace(os.sep, "/")
    if os.path.isabs(path):
        return os.path.basename(path)
    return path.replace(os.sep, "/")


def normalize_material_set(materials=None, *, base_dir=None, **_kwargs):
    """Normalize a name-to-hash mapping, paths, or a directory of text files."""
    if materials is None:
        return {}

    if isinstance(materials, (str, os.PathLike)):
        path = os.fspath(materials)
        if os.path.isdir(path):
            collected = {}
            for root, _dirs, files in os.walk(path):
                for filename in sorted(files):
                    file_path = os.path.join(root, filename)
                    name = _artifact_name(file_path, path)
                    collected[name] = _hash_file(file_path)
            return dict(sorted(collected.items()))
        name = _artifact_name(path, base_dir)
        return {name: _hash_file(path)}

    if isinstance(materials, (Link, Metadata)):
        return collect_signed_material_set(materials, base_dir=base_dir)

    if isinstance(materials, (list, tuple, set)):
        normalized = {}
        for index, item in enumerate(materials):
            if isinstance(item, str):
                if os.path.exists(item):
                    name = _artifact_name(item, base_dir)
                    hashes = _hash_file(item)
                else:
                    name = item
                    raise securesystemslib.exceptions.FormatError(
                        f"Material path does not exist: {item}"
                    )
            elif isinstance(item, (list, tuple)) and len(item) == 2:
                name, hashes = item
                hashes = _normalize_hashes(hashes)
            elif isinstance(item, dict):
                name = item.get("name") or item.get("artifact")
                if not name:
                    raise securesystemslib.exceptions.FormatError(
                        f"Material entry {index} is missing its name"
                    )
                hashes = item.get("hashes") or item.get("artifact_hashes")
                if hashes is None and os.path.exists(name):
                    hashes = _hash_file(name)
                else:
                    hashes = _normalize_hashes(hashes)
            else:
                raise securesystemslib.exceptions.FormatError(
                    f"Unsupported material entry at index {index}"
                )
            normalized[name] = hashes
        return dict(sorted(normalized.items()))

    if isinstance(materials, dict):
        if _looks_like_link_collection(materials):
            return collect_signed_material_set(materials, base_dir=base_dir)
        normalized = {}
        for name, hashes in materials.items():
            if hashes is None and base_dir:
                hashes = _hash_file(os.path.join(base_dir, name))
            else:
                hashes = _normalize_hashes(hashes)
            normalized[name] = hashes
        return dict(sorted(normalized.items()))

    raise securesystemslib.exceptions.FormatError(
        "Materials must be a mapping, list, directory, Link, or Metadata"
    )


def _link_payload(candidate):
    if hasattr(candidate, "get_payload"):
        try:
            candidate = candidate.get_payload()
        except Exception:  # noqa: BLE001
            return None
    if hasattr(candidate, "signed") and hasattr(candidate.signed, "materials"):
        return candidate.signed
    if hasattr(candidate, "materials"):
        return candidate
    if isinstance(candidate, dict):
        if isinstance(candidate.get("signed"), dict):
            return candidate["signed"]
        if "materials" in candidate:
            return candidate
    return None


def _looks_like_link_collection(value):
    if not isinstance(value, dict):
        return False
    payload = _link_payload(value)
    if payload is not None:
        return True
    for item in value.values():
        if _link_payload(item) is not None:
            return True
        if isinstance(item, dict):
            if any(_link_payload(child) is not None for child in item.values()):
                return True
    return False


def _iter_link_payloads(source, seen=None):
    if seen is None:
        seen = set()
    source_id = id(source)
    if source_id in seen:
        return
    seen.add(source_id)

    payload = _link_payload(source)
    if payload is not None:
        yield payload
        return

    if isinstance(source, dict):
        for value in source.values():
            yield from _iter_link_payloads(value, seen)
    elif isinstance(source, (list, tuple, set)):
        for value in source:
            yield from _iter_link_payloads(value, seen)


def collect_signed_material_set(
    links=None,
    steps=None,
    *,
    material_type="materials",
    artifact_type=None,
    raise_on_conflict=True,
    **_kwargs,
):
    """Collect the complete signed material set from verified in-toto links."""
    selected_type = artifact_type or material_type or "materials"
    types = (
        ("materials", "products")
        if selected_type == "both"
        else (selected_type,)
    )
    selected_steps = set(steps or [])
    sources = links
    if selected_steps and isinstance(links, dict):
        sources = [links.get(step) for step in selected_steps]

    full_set = {}
    for link in _iter_link_payloads(sources):
        for current_type in types:
            artifacts = getattr(link, current_type, None)
            if artifacts is None and isinstance(link, dict):
                artifacts = link.get(current_type, {})
            if not isinstance(artifacts, dict):
                continue
            for path, hashes in artifacts.items():
                artifact_id = (
                    current_type + ":" + path
                    if selected_type == "both"
                    else path
                )
                normalized = _normalize_hashes(hashes)
                existing = full_set.get(artifact_id)
                if existing is not None and existing != normalized:
                    if raise_on_conflict:
                        raise MaterialSetMismatchError(
                            "Verified links disagree about material "
                            + repr(artifact_id)
                        )
                    continue
                full_set[artifact_id] = normalized
    return dict(sorted(full_set.items()))


collect_signed_materials = collect_signed_material_set
collect_material_full_set = collect_signed_material_set


def material_set_digest(materials=None, **kwargs):
    """Return the SHA-256 digest of the canonical complete material set."""
    normalized = normalize_material_set(materials, **kwargs)
    return hashlib.sha256(_canonical_json(normalized)).hexdigest()


full_set_digest = material_set_digest
compute_full_set_digest = material_set_digest
signed_materials_digest = material_set_digest


def diff_material_sets(expected=None, current=None, **kwargs):
    """Return added, removed, and hash-replaced material names."""
    if current is None and expected is not None:
        expected, current = current, expected
    expected_set = normalize_material_set(expected, **kwargs)
    current_set = normalize_material_set(current, **kwargs)
    expected_names = set(expected_set)
    current_names = set(current_set)
    replaced = sorted(
        name
        for name in expected_names & current_names
        if expected_set[name] != current_set[name]
    )
    return {
        "added": sorted(current_names - expected_names),
        "removed": sorted(expected_names - current_names),
        "replaced": replaced,
        "changed": sorted((current_names ^ expected_names) | set(replaced)),
        "unchanged": sorted(
            name
            for name in expected_names & current_names
            if expected_set[name] == current_set[name]
        ),
    }


diff_full_sets = diff_material_sets


def verify_full_material_set(
    materials=None,
    expected=None,
    *,
    expected_digest=None,
    recorded_digest=None,
    full_set_digest=None,
    raise_on_mismatch=True,
    **kwargs,
):
    """Recheck the entire signed set, including materials not sampled."""
    current = normalize_material_set(materials, **kwargs)
    current_digest = hashlib.sha256(_canonical_json(current)).hexdigest()
    baseline_digest = expected_digest or recorded_digest or full_set_digest
    changes = {}
    baseline_expected = None

    if expected is not None:
        baseline_expected = normalize_material_set(expected, **kwargs)
        expected_digest_from_set = hashlib.sha256(
            _canonical_json(baseline_expected)
        ).hexdigest()
        if baseline_digest is None:
            baseline_digest = expected_digest_from_set
        changes = diff_material_sets(baseline_expected, current, **kwargs)

    digest_matches = baseline_digest in (None, current_digest)
    if changes:
        set_matches = not (
            changes["added"] or changes["removed"] or changes["replaced"]
        )
    else:
        set_matches = True

    valid = digest_matches and set_matches
    result = SamplingResult(
        passed=valid,
        valid=valid,
        current_digest=current_digest,
        full_set_digest=current_digest,
        expected_digest=baseline_digest,
        changes=changes,
        added=changes.get("added", []),
        removed=changes.get("removed", []),
        replaced_materials=changes.get("replaced", []),
        full_set_changed=not valid and baseline_digest is not None,
        requires_full_set_review=not valid and baseline_digest is not None,
    )
    if not valid and raise_on_mismatch:
        result.raise_for_status()
    return result


verify_material_full_set = verify_full_material_set
verify_signed_material_full_set = verify_full_material_set
verify_material_set = verify_full_material_set


def _draw_policy(seed, sample_size, cutoff, policy, kwargs):
    if policy is not None:
        return SamplingPolicy.read(policy)

    if isinstance(seed, SamplingPolicy):
        return seed

    if isinstance(seed, dict) and (
        "seed" in seed
        or "cutoff" in seed
        or "release_cutoff" in seed
        or "sample_size" in seed
        or "size" in seed
    ):
        return SamplingPolicy.read(seed)

    return SamplingPolicy(
        seed=seed,
        sample_size=sample_size or kwargs.pop("size", None),
        cutoff=cutoff or kwargs.pop("release_cutoff", None),
        **kwargs,
    )


def compute_sample_draw(
    seed=None,
    materials=None,
    sample_size=None,
    *,
    cutoff=None,
    policy=None,
    base_dir=None,
    **kwargs,
):
    """Compute a fixed-seed HMAC ranking over the complete material set."""
    policy_like = isinstance(seed, SamplingPolicy) or (
        isinstance(seed, dict)
        and (
            "seed" in seed
            or "cutoff" in seed
            or "release_cutoff" in seed
            or "sample_size" in seed
            or "size" in seed
        )
    )
    if materials is None and seed is not None and not policy_like:
        materials = seed
        seed = None
    elif (policy_like and materials is not None) or policy_like:
        policy = seed
        seed = None

    policy_obj = _draw_policy(seed, sample_size, cutoff, policy, kwargs)
    normalized = normalize_material_set(materials, base_dir=base_dir)
    if not normalized:
        raise SamplingVerificationError(
            "Cannot draw a sample from an empty signed material set"
        )

    current_digest = hashlib.sha256(_canonical_json(normalized)).hexdigest()
    ranked = []
    for name, hashes in normalized.items():
        rank_message = {
            "algorithm": policy_obj.algorithm,
            "full_set_digest": current_digest,
            "material": name,
            "hashes": hashes,
        }
        rank = hmac.new(
            policy_obj.seed.encode("utf-8"),
            _canonical_json(rank_message),
            hashlib.sha256,
        ).hexdigest()
        ranked.append(
            {
                "material": name,
                "name": name,
                "hashes": hashes,
                "rank": rank,
            }
        )

    ranked.sort(key=lambda entry: (entry["rank"], entry["name"]))
    draw_size = min(policy_obj.sample_size, len(ranked))
    selection = ranked[:draw_size]
    selected = [entry["name"] for entry in selection]
    cutoff_value = policy_obj.get("cutoff")
    cutoff_iso = _isoformat(cutoff_value) if cutoff_value else None

    draw_digest = hashlib.sha256(
        _canonical_json(
            {
                "protocol": SAMPLING_PROTOCOL_VERSION,
                "algorithm": policy_obj.algorithm,
                "seed": policy_obj.seed,
                "cutoff": cutoff_iso,
                "sample_size": draw_size,
                "full_set_digest": current_digest,
                "selected": selected,
                "selection": selection,
            }
        )
    ).hexdigest()

    return SamplingDraw(
        protocol=SAMPLING_PROTOCOL_VERSION,
        version=SAMPLING_PROTOCOL_VERSION,
        algorithm=policy_obj.algorithm,
        seed=policy_obj.seed,
        batch_seed=policy_obj.seed,
        cutoff=cutoff_iso,
        release_cutoff=cutoff_iso,
        sample_size=draw_size,
        requested_sample_size=policy_obj.sample_size,
        full_set=normalized,
        materials=normalized,
        full_set_digest=current_digest,
        selected=selected,
        sample=selected,
        selection=selection,
        draw_digest=draw_digest,
        sample_digest=draw_digest,
        digest=draw_digest,
        policy=dict(policy_obj),
        policy_digest=policy_obj.digest,
    )


compute_draw_sheet = compute_sample_draw
create_draw_sheet = compute_sample_draw
fixed_batch_sample = compute_sample_draw
derive_fixed_sample = compute_sample_draw
select_materials_for_review = compute_sample_draw


def recompute_draw_sheet(draw_sheet, materials=None, **kwargs):
    """Recompute a draw from its fixed seed and signed full set."""
    draw = SamplingDraw.read(draw_sheet)
    source_materials = (
        materials
        if materials is not None
        else draw.get("full_set") or draw.get("materials")
    )
    return compute_sample_draw(
        seed=draw.get("seed") or draw.get("batch_seed"),
        materials=source_materials,
        sample_size=draw.get("sample_size"),
        cutoff=draw.get("cutoff") or draw.get("release_cutoff"),
        **kwargs,
    )


def verify_draw_sheet(
    draw_sheet=None,
    materials=None,
    *,
    full_set=None,
    raise_on_invalid=True,
    **kwargs,
):
    """Verify that a draw sheet is reproducible from seed and full set."""
    recorded = SamplingDraw.read(draw_sheet)
    source_materials = materials if materials is not None else full_set
    recomputed = recompute_draw_sheet(recorded, source_materials, **kwargs)
    digest_matches = recorded.get("draw_digest") in (
        None,
        recomputed.draw_digest,
    )
    set_matches = recorded.get("full_set_digest") in (
        None,
        recomputed.full_set_digest,
    )
    selected_matches = recorded.get("selected") in (
        None,
        recomputed.selected,
    ) and recorded.get("sample") in (None, recomputed.sample)
    valid = digest_matches and set_matches and selected_matches
    result = SamplingResult(
        passed=valid,
        valid=valid,
        draw=recomputed,
        draw_sheet=recomputed,
        selected=recomputed.selected,
        full_set_digest=recomputed.full_set_digest,
        draw_digest=recomputed.draw_digest,
        digest=recomputed.draw_digest,
    )
    if not valid and raise_on_invalid:
        raise SamplingVerificationError(
            "Draw sheet is not reproducible from seed and full set",
            result=result,
        )
    return result


def _first_review_field(raw, names):
    for name in names:
        value = raw.get(name)
        if value not in (None, ""):
            return value
    return None


def verify_sampling_review(  # noqa: PLR0912, PLR0913, PLR0915
    materials=None,
    confirmations=None,
    cutoff=None,
    *,
    seed=None,
    sample_size=DEFAULT_SAMPLE_SIZE,
    threshold=1,
    expected_full_set_digest=None,
    recorded_full_set_digest=None,
    expected_draw_digest=None,
    draw_sheet=None,
    base_dir=None,
    raise_on_failure=True,
    review_metadata=None,
    write_draw_sheet=None,
    write_result=None,
    **kwargs,
):
    """Verify deterministic sampling, the complete signed set, and timing."""
    cutoff = (
        cutoff
        or kwargs.pop("deadline", None)
        or kwargs.pop("release_cutoff", None)
    )
    if confirmations is None:
        confirmations = (
            review_metadata
            if review_metadata is not None
            else kwargs.pop("reviews", None)
        )

    recorded_draw = None
    if draw_sheet is not None:
        recorded_draw = SamplingDraw.read(draw_sheet)
        expected_full_set_digest = (
            expected_full_set_digest or recorded_draw.full_set_digest
        )
        expected_draw_digest = expected_draw_digest or recorded_draw.draw_digest
        seed = seed or recorded_draw.get("seed")
        if sample_size == DEFAULT_SAMPLE_SIZE:
            sample_size = recorded_draw.get("sample_size", sample_size)
        cutoff = cutoff or recorded_draw.get("cutoff")

    seed = seed or FIXED_BATCH_SEED
    normalized = normalize_material_set(materials, base_dir=base_dir)
    baseline_materials = None
    if recorded_draw is not None:
        baseline_materials = recorded_draw.get("full_set") or recorded_draw.get(
            "materials"
        )
    full_check = verify_full_material_set(
        normalized,
        expected=baseline_materials,
        expected_digest=(expected_full_set_digest or recorded_full_set_digest),
        raise_on_mismatch=False,
    )
    draw = compute_sample_draw(
        seed=seed,
        materials=normalized,
        sample_size=sample_size,
        cutoff=cutoff,
        base_dir=base_dir,
        threshold=threshold,
        **kwargs,
    )

    draw_matches = True
    if expected_draw_digest is not None:
        draw_matches = expected_draw_digest == draw.draw_digest
    if recorded_draw is not None:
        draw_matches = draw_matches and (
            recorded_draw.get("selected") in (None, draw.selected)
        )

    accepted = {}
    accepted_records = []
    late_records = []
    invalid_records = []

    for raw in _iter_confirmations(confirmations):
        artifact = _first_review_field(
            raw,
            ("artifact", "material", "name", "path", "target", "filename"),
        )
        reviewed_at = _first_review_field(
            raw,
            (
                "reviewed_at",
                "review_time",
                "timestamp",
                "confirmed_at",
                "signed_at",
                "time",
            ),
        )
        reviewer = _first_review_field(
            raw, ("reviewer", "reviewer_id", "keyid", "key_id", "signer")
        )
        record = {
            "artifact": artifact,
            "reviewed_at": reviewed_at,
            "reviewer": reviewer,
        }

        if artifact not in draw.selected:
            invalid_records.append(
                {**record, "reason": "Confirmation is not for a drawn material"}
            )
            continue

        binding_error = None
        raw_full_digest = _first_review_field(
            raw, ("full_set_digest", "material_set_digest")
        )
        raw_draw_digest = _first_review_field(
            raw, ("draw_digest", "draw_sheet_digest", "sample_digest")
        )
        raw_cutoff = _first_review_field(
            raw, ("cutoff", "release_cutoff", "deadline")
        )
        if raw_full_digest and raw_full_digest != draw.full_set_digest:
            binding_error = "Confirmation is bound to another material full set"
        elif raw_draw_digest and raw_draw_digest != draw.draw_digest:
            binding_error = "Confirmation is bound to another sample draw"
        elif raw_cutoff:
            try:
                if _isoformat(raw_cutoff) != _isoformat(cutoff):
                    binding_error = "Confirmation is bound to another cutoff"
            except securesystemslib.exceptions.FormatError:
                binding_error = "Confirmation has a malformed cutoff binding"
        elif raw.get("signature_valid") is False:
            binding_error = "Review signature is not valid"

        if binding_error:
            invalid_records.append({**record, "reason": binding_error})
            continue

        try:
            timing = verify_review_time(
                reviewed_at, cutoff, raise_on_late=False
            )
        except securesystemslib.exceptions.FormatError as exc:
            invalid_records.append({**record, "reason": str(exc)})
            continue

        record.update(
            {
                "reviewed_at": timing.reviewed_at,
                "cutoff": timing.cutoff,
                "status": timing.status,
                "full_set_digest": draw.full_set_digest,
                "draw_digest": draw.draw_digest,
            }
        )
        if timing.late:
            late_records.append(record)
            continue

        accepted.setdefault(artifact, []).append(record)
        accepted_records.append(record)

    missing = []
    for artifact in draw.selected:
        records = accepted.get(artifact, [])
        distinct_reviewers = {
            record.get("reviewer") or id(record) for record in records
        }
        if len(distinct_reviewers) < threshold:
            missing.append(artifact)

    valid = (
        bool(normalized)
        and full_check.passed
        and draw_matches
        and not missing
        and not invalid_records
    )
    status = "passed" if valid else "failed"
    result = SamplingResult(
        passed=valid,
        valid=valid,
        status=status,
        seed=seed,
        batch_seed=seed,
        cutoff=_isoformat(cutoff) if cutoff else None,
        release_cutoff=_isoformat(cutoff) if cutoff else None,
        sample_size=draw.sample_size,
        threshold=threshold,
        selected=draw.selected,
        sample=draw.selected,
        draw=draw,
        draw_sheet=draw,
        full_set=normalized,
        materials=normalized,
        full_set_digest=draw.full_set_digest,
        draw_digest=draw.draw_digest,
        digest=draw.draw_digest,
        expected_draw_digest=expected_draw_digest,
        draw_matches=draw_matches,
        changes=full_check.changes,
        added=full_check.added,
        removed=full_check.removed,
        replaced_materials=full_check.replaced_materials,
        full_set_changed=full_check.full_set_changed,
        requires_full_set_review=bool(full_check.full_set_changed),
        accepted=accepted,
        accepted_reviews=accepted_records,
        on_time_reviews=accepted_records,
        late=late_records,
        late_reviews=late_records,
        recheck_queue=late_records,
        missing=missing,
        invalid=invalid_records,
    )

    if write_draw_sheet:
        draw.dump(write_draw_sheet)
    if write_result:
        result.dump(write_result)
    if raise_on_failure:
        result.raise_for_status()
    return result


verify_batch_review = verify_sampling_review
verify_batch_sampling = verify_sampling_review
verify_sampling_protocol = verify_sampling_review
verify_release_sampling = verify_sampling_review
check_sampling_acceptance = verify_sampling_review


def verify_sampling_acceptance(
    policy=None,
    full_set=None,
    review_metadata=None,
    review_confirmations=None,
    draw_sheet=None,
    raise_on_failure=True,
    write_draw_sheet=None,
    write_result=None,
    **kwargs,
):
    """Policy-shaped compatibility wrapper around verify_sampling_review."""
    if (
        policy is None
        and isinstance(full_set, dict)
        and ("seed" in full_set or "cutoff" in full_set)
    ):
        policy, full_set = full_set, None

    policy_obj = (
        SamplingPolicy.read(policy)
        if policy is not None
        else SamplingPolicy(
            seed=kwargs.pop("seed", None),
            sample_size=kwargs.pop("sample_size", kwargs.pop("size", None)),
            cutoff=kwargs.pop(
                "cutoff",
                kwargs.pop("release_cutoff", kwargs.pop("deadline", None)),
            ),
            threshold=kwargs.pop("threshold", 1),
        )
    )
    return verify_sampling_review(
        full_set,
        review_confirmations
        if review_confirmations is not None
        else review_metadata,
        policy_obj.get("cutoff"),
        seed=policy_obj.seed,
        sample_size=policy_obj.sample_size,
        threshold=policy_obj.threshold,
        draw_sheet=draw_sheet,
        raise_on_failure=raise_on_failure,
        write_draw_sheet=write_draw_sheet,
        write_result=write_result,
        **kwargs,
    )


verify_sampling_for_links = verify_sampling_acceptance


def _confirmation_mapping(item):
    if isinstance(item, (Link, Metadata)) or hasattr(item, "get_payload"):
        try:
            payload = (
                item.get_payload() if hasattr(item, "get_payload") else item
            )
        except Exception:  # noqa: BLE001
            payload = item
        byproducts = getattr(payload, "byproducts", None)
        if byproducts is None and isinstance(payload, dict):
            byproducts = payload.get("byproducts", {})
        raw = dict(byproducts) if isinstance(byproducts, dict) else {}
        if isinstance(payload, dict):
            for key, value in payload.items():
                if key != "byproducts":
                    raw.setdefault(key, value)
        return raw

    if hasattr(item, "byproducts"):
        byproducts = item.byproducts
        raw = dict(byproducts) if isinstance(byproducts, dict) else {}
        return raw

    if isinstance(item, dict):
        raw = dict(item)
        byproducts = raw.get("byproducts")
        if isinstance(byproducts, dict):
            merged = dict(byproducts)
            nested = merged.get("sampling")
            if isinstance(nested, dict):
                merged.update(nested)
            merged.update(raw)
            return merged
        return raw

    if isinstance(item, str):
        return {"reviewed_at": item}

    raise securesystemslib.exceptions.FormatError(
        "Review confirmation must be a mapping, Link, Metadata, or timestamp"
    )


def _iter_confirmations(confirmations):
    if confirmations is None:
        return

    if isinstance(confirmations, dict):
        looks_like_record = any(
            key in confirmations
            for key in (
                "artifact",
                "material",
                "name",
                "path",
                "reviewed_at",
                "review_time",
                "timestamp",
                "confirmed_at",
            )
        )
        if looks_like_record:
            yield confirmations
            return

        for artifact, value in confirmations.items():
            if isinstance(value, (list, tuple, set)):
                for item in value:
                    raw = _confirmation_mapping(item)
                    raw.setdefault("artifact", artifact)
                    yield raw
            else:
                raw = _confirmation_mapping(value)
                raw.setdefault("artifact", artifact)
                yield raw
        return

    if isinstance(confirmations, (list, tuple, set)):
        for item in confirmations:
            yield from _iter_confirmations(item)
        return

    yield _confirmation_mapping(confirmations)


def _first_review_field(raw, names):
    for name in names:
        value = raw.get(name)
        if value not in (None, ""):
            return value
    return None


def _review_mapping(item):
    if hasattr(item, "get_payload"):
        try:
            item = item.get_payload()
        except Exception:  # noqa: BLE001
            item = None

    if hasattr(item, "byproducts"):
        byproducts = item.byproducts or {}
        raw = dict(byproducts) if isinstance(byproducts, dict) else {}
    elif isinstance(item, dict):
        raw = dict(item)
    elif isinstance(item, str):
        raw = {"reviewed_at": item}
    else:
        raise securesystemslib.exceptions.FormatError(
            "Review confirmation must be a mapping, Link, Metadata, or time"
        )

    nested = raw.get("sampling")
    if isinstance(nested, dict):
        merged = dict(nested)
        merged.update(raw)
        raw = merged

    byproducts = raw.get("byproducts")
    if isinstance(byproducts, dict):
        merged = dict(byproducts)
        merged.update(raw)
        raw = merged
    return raw


def _iter_review_confirmations(confirmations):
    if confirmations is None:
        return

    if isinstance(confirmations, dict):
        looks_like_record = any(
            key in confirmations
            for key in (
                "artifact",
                "material",
                "name",
                "path",
                "target",
                "reviewed_at",
                "review_time",
                "timestamp",
                "confirmed_at",
            )
        )
        if looks_like_record:
            yield confirmations
            return

        for artifact, value in confirmations.items():
            if isinstance(value, (list, tuple, set)):
                for item in value:
                    raw = _review_mapping(item)
                    raw.setdefault("artifact", artifact)
                    yield raw
            else:
                raw = _review_mapping(value)
                raw.setdefault("artifact", artifact)
                yield raw
        return

    if isinstance(confirmations, (list, tuple, set)):
        for item in confirmations:
            yield _review_mapping(item)
        return

    yield _review_mapping(confirmations)


def _normalize_review_confirmation(item, draw, cutoff_dt):
    raw = _review_mapping(item)
    artifact = _first_review_field(
        raw,
        (
            "artifact",
            "material",
            "material_name",
            "name",
            "path",
            "target",
            "filename",
        ),
    )
    reviewed_at = _first_review_field(
        raw,
        (
            "reviewed_at",
            "review_time",
            "review_timestamp",
            "timestamp",
            "confirmed_at",
            "confirmation_time",
            "signed_at",
            "time",
        ),
    )
    reviewer = _first_review_field(
        raw, ("reviewer", "reviewer_id", "keyid", "key_id", "signer")
    )
    draw_digest = _first_review_field(
        raw,
        ("draw_digest", "draw_sheet_digest", "sample_digest"),
    )
    full_set_digest = _first_review_field(
        raw, ("full_set_digest", "materials_digest", "set_digest")
    )
    confirmation_cutoff = _first_review_field(
        raw, ("cutoff", "release_cutoff", "deadline")
    )
    seed = _first_review_field(raw, ("seed", "batch_seed"))

    if reviewed_at is None:
        raise SamplingVerificationError(
            "Review confirmation is missing its review timestamp"
        )
    reviewed_dt = parse_review_timestamp(reviewed_at, "reviewed_at")

    selected = list(draw.get("selected", []))
    if artifact is None:
        if len(selected) == 1:
            artifact = selected[0]
        else:
            raise SamplingVerificationError(
                "Review confirmation is missing its sampled artifact name"
            )

    artifact = str(artifact)
    artifact_candidates = {artifact}
    if ":" in artifact:
        artifact_candidates.add(artifact.split(":", 1)[1])
    artifact_candidates.update(
        candidate
        for candidate in selected
        if candidate.endswith("/" + artifact) or candidate == artifact
    )
    matched = artifact_candidates.intersection(selected)
    if not matched:
        raise SamplingVerificationError(
            "Review confirmation references an artifact not in the draw: "
            + artifact
        )
    artifact = sorted(matched)[0]

    expected_draw_digest = draw.get("draw_digest") or draw.get("sample_digest")
    if (
        draw_digest
        and expected_draw_digest
        and draw_digest != expected_draw_digest
    ):
        raise SamplingVerificationError(
            "Review confirmation is bound to a different sampling draw"
        )
    if (
        full_set_digest
        and draw.get("full_set_digest")
        and full_set_digest != draw["full_set_digest"]
    ):
        raise SamplingVerificationError(
            "Review confirmation is bound to a different material full set"
        )
    if confirmation_cutoff and cutoff_dt is not None:
        confirmation_cutoff_dt = parse_review_timestamp(
            confirmation_cutoff, "cutoff"
        )
        if confirmation_cutoff_dt != cutoff_dt:
            raise SamplingVerificationError(
                "Review confirmation is bound to a different release cutoff"
            )
    if seed and draw.get("seed") and seed != draw["seed"]:
        raise SamplingVerificationError(
            "Review confirmation is bound to a different batch seed"
        )
    if raw.get("signature_valid") is False or raw.get("verified") is False:
        raise SignatureVerificationError(
            "Review confirmation signature was not verified"
        )

    on_time = cutoff_dt is None or reviewed_dt <= cutoff_dt
    return {
        "artifact": artifact,
        "reviewer": reviewer,
        "reviewed_at": _isoformat(reviewed_dt),
        "on_time": on_time,
        "late": not on_time,
        "status": "on-time" if on_time else "late",
        "draw_digest": draw_digest or expected_draw_digest,
        "full_set_digest": full_set_digest or draw.get("full_set_digest"),
    }


BATCH_SEED = FIXED_BATCH_SEED
SAMPLING_SEED = FIXED_BATCH_SEED


def get_fixed_batch_seed(batch_id=None):
    """Return the protocol seed, optionally namespaced by batch identifier."""
    if batch_id in (None, ""):
        return FIXED_BATCH_SEED
    return f"{FIXED_BATCH_SEED}/{batch_id}"


def verify_batch_seed(
    seed=None,
    expected_seed=None,
    *,
    draw_sheet=None,
    raise_on_mismatch=True,
):
    """Ensure a draw/confirmation still uses the pre-agreed batch seed."""
    recorded = SamplingDraw.read(draw_sheet) if draw_sheet else None
    expected = (
        expected_seed
        or (recorded.get("seed") if recorded else None)
        or FIXED_BATCH_SEED
    )
    actual = seed or (recorded.get("seed") if recorded else FIXED_BATCH_SEED)
    valid = hmac.compare_digest(str(actual), str(expected))
    result = SamplingResult(
        passed=valid,
        valid=valid,
        seed=actual,
        expected_seed=expected,
        batch_seed=actual,
    )
    if not valid and raise_on_mismatch:
        raise SamplingVerificationError(
            "Batch seed does not match the fixed protocol seed",
            result=result,
        )
    return result


verify_fixed_batch_seed = verify_batch_seed


def verify_signed_materials(
    metadata=None,
    keys_dict=None,
    materials=None,
    **kwargs,
):
    """Verify build/link signatures when keys are supplied, then hash the set."""
    signatures_verified = False
    if keys_dict is not None:
        verify_metadata_signatures(metadata, keys_dict)
        signatures_verified = True

    source = materials if materials is not None else metadata
    material_set = normalize_material_set(source, **kwargs)
    digest = hashlib.sha256(_canonical_json(material_set)).hexdigest()
    return SamplingResult(
        passed=True,
        valid=True,
        signatures_verified=signatures_verified,
        materials=material_set,
        full_set=material_set,
        full_set_digest=digest,
    )


verify_signed_build_materials = verify_signed_materials


def verify_signed_build_and_review(
    metadata=None,
    keys_dict=None,
    **sampling_kwargs,
):
    """Verify the build signature first and then enforce sampling review."""
    verify_metadata_signatures(metadata, keys_dict)
    return verify_sampling_review(**sampling_kwargs)


verify_build_signature_and_sampling = verify_signed_build_and_review


def select_sample(*args, **kwargs):
    """Return only the deterministic selected material names."""
    return compute_sample_draw(*args, **kwargs).selected


sample_materials = select_sample
deterministic_sample = select_sample
