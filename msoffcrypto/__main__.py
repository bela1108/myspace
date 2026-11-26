import argparse
import contextlib
import getpass
import json
import logging
import sys

import olefile

from msoffcrypto import OfficeFile, exceptions
from msoffcrypto.format.ooxml import OOXMLFile, _is_ooxml
from msoffcrypto import receipt

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


def _get_version():
    if sys.version_info >= (3, 8):
        from importlib import metadata

        return metadata.version("msoffcrypto-tool")
    else:
        import pkg_resources

        return pkg_resources.get_distribution("msoffcrypto-tool").version


def ifWIN32SetBinary(io):
    if sys.platform == "win32":
        import msvcrt
        import os

        msvcrt.setmode(io.fileno(), os.O_BINARY)


def is_encrypted(file):
    r"""
    Test if the file is encrypted.

        >>> f = open("tests/inputs/plain.doc", "rb")
        >>> is_encrypted(f)
        False
    """
    # TODO: Validate file
    if not olefile.isOleFile(file):
        return False

    file = OfficeFile(file)

    return file.is_encrypted()


parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group(required=False)
group.add_argument("-p", "--password", nargs="?", const="", dest="password", help="password text")
group.add_argument("-t", "--test", dest="test_encrypted", action="store_true", help="test if the file is encrypted")
group.add_argument(
    "--inspect",
    "--format-observation",
    dest="inspect",
    action="store_true",
    help="print a read-only format observation",
)
group.add_argument(
    "--receipt",
    "--ledger",
    "--read-only-receipt",
    dest="receipt",
    metavar="PATH",
    help="create, resume, or query a receipt",
)
parser.add_argument("-e", dest="encrypt", action="store_true", help="encryption mode (default is false)")
parser.add_argument("-v", dest="verbose", action="store_true", help="print verbose information")
parser.add_argument("infile", nargs="?", type=argparse.FileType("rb"), help="input file")
parser.add_argument("outfile", nargs="?", type=argparse.FileType("wb"), help="output file (if blank, stdout is used)")
parser.add_argument("--sample", dest="samples", action="append", default=None, help="sample to observe (receipt mode; repeatable)")
parser.add_argument("--case-id", dest="case_id", default=None, help="case identifier for a new receipt")
parser.add_argument("--no-resume", dest="no_resume", action="store_true", help="observe samples without renewing prior confirmations")
parser.add_argument("--interrupt-after", dest="interrupt_after", type=int, default=None, help="stop after N observations for recovery testing")
parser.add_argument("--status", dest="receipt_status", action="store_true", help="print the receipt state")
parser.add_argument("--correct", dest="correct", metavar="OBSERVATION_ID", help="append a correction")
parser.add_argument("--renew", dest="renew", metavar="OBSERVATION_ID", help="renew a confirmed conclusion once")
parser.add_argument("--verify", dest="verify", action="store_true", help="recheck recorded public properties against samples")
parser.add_argument("--field", dest="field", default=None, help="correction field")
parser.add_argument("--value", dest="value", default=None, help="correction value")
parser.add_argument("--reason", dest="reason", default=None, help="correction or renewal reason")
parser.add_argument("--actor", dest="actor", default=None, help="reviewer identity")


def _json_output(payload, outfile=None):
    text = payload.to_json() if hasattr(payload, "to_json") else json.dumps(payload, indent=2, ensure_ascii=False)
    target = outfile if outfile is not None else sys.stdout
    if hasattr(target, "buffer") and not hasattr(target, "encoding"):
        target = target.buffer
    if hasattr(target, "write"):
        try:
            target.write(text.encode("utf-8") if not hasattr(target, "encoding") else text)
            if hasattr(target, "flush"):
                target.flush()
        except TypeError:
            target.write(text)


def _receipt_command(args):
    path = args.receipt
    if args.receipt_status:
        current = receipt.load_receipt(path, read_only=True)
        _json_output(current.to_dict(), args.outfile)
        return 0

    if args.correct:
        if args.field is None:
            parser.error("--correct requires --field")
        current = receipt.load_receipt(path)
        value = args.value
        with contextlib.suppress(Exception):
            if isinstance(value, str) and value.lstrip().startswith(("{", "[", "true", "false", "null")) or (
                isinstance(value, str) and value.strip().lstrip("-").isdigit()
            ):
                value = json.loads(value)
        event = current.correct(args.correct, args.field, value, reason=args.reason, actor=args.actor)
        _json_output(event, args.outfile)
        return 0

    if args.renew:
        current = receipt.load_receipt(path)
        result = current.renew(args.renew, actor=args.actor, reason=args.reason)
        _json_output(result, args.outfile)
        return 0 if result.get("renewed") else 1

    if args.verify:
        result = receipt.verify_receipt(path)
        _json_output(result, args.outfile)
        return 0 if result.get("ok") else 1

    samples = list(args.samples or [])
    if not samples and args.infile is not None:
        samples.append(args.infile.name)
    if not samples:
        existing = receipt.load_receipt(path)
        if not existing.observations and not existing.state.get("planned_samples"):
            parser.error("receipt mode requires at least one --sample")
        current = receipt.resume_receipt(path)
        _json_output(current.to_dict(), args.outfile)
        return 0
    try:
        current = receipt.write_receipt(
            samples,
            path,
            case_id=args.case_id,
            resume=not args.no_resume,
            interrupt_after=args.interrupt_after,
        )
    except receipt.InterruptedWriteError as exc:
        print(
            "receipt interrupted after {} complete observations: {}".format(
                getattr(exc, "observations_written", exc.events_written), exc
            ),
            file=sys.stderr,
        )
        return 75
    _json_output(current.to_dict(), args.outfile)
    return 0


def main():
    args = parser.parse_args()

    if args.verbose:
        logger.removeHandler(logging.NullHandler())
        logging.basicConfig(level=logging.DEBUG, format="%(message)s")
        version = _get_version()
        logger.debug("Version: {}".format(version))

    if not (
        args.password is not None
        or args.test_encrypted
        or args.inspect
        or args.receipt
        or args.receipt_status
        or args.verify
        or args.correct
        or args.renew
    ):
        parser.error("one of --password, --test, --inspect, --receipt, --status, --verify, --correct, or --renew is required")

    if not args.receipt and (args.receipt_status or args.verify or args.correct or args.renew):
        if args.infile is None:
            parser.error("this receipt command requires a receipt path")
        args.receipt = args.infile.name

    if args.inspect:
        if args.infile is None:
            parser.error("--inspect requires an input file")
        observation = receipt.inspect_file(args.infile)
        _json_output(observation, args.outfile)
        return

    if args.receipt:
        sys.exit(_receipt_command(args))

    if args.test_encrypted:
        if not is_encrypted(args.infile):
            print("{}: not encrypted".format(args.infile.name), file=sys.stderr)
            sys.exit(1)
        else:
            logger.debug("{}: encrypted".format(args.infile.name))
        return

    if args.password:
        password = args.password
    else:
        password = getpass.getpass()

    if args.outfile is None:
        ifWIN32SetBinary(sys.stdout)
        if hasattr(sys.stdout, "buffer"):  # For Python 2
            args.outfile = sys.stdout.buffer
        else:
            args.outfile = sys.stdout

    if args.encrypt:
        if not _is_ooxml(args.infile):
            raise exceptions.FileFormatError("Not an OOXML file")

        # OOXML is the only format we support for encryption
        file = OOXMLFile(args.infile)

        file.encrypt(password, args.outfile)
    else:
        if not olefile.isOleFile(args.infile):
            raise exceptions.FileFormatError("Not an OLE file")

        file = OfficeFile(args.infile)
        file.load_key(password=password)

        file.decrypt(args.outfile)


if __name__ == "__main__":
    main()
