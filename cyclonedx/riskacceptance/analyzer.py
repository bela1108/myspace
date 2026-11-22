# This file is part of CycloneDX Python Library
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.

"""Offline classification of risk-acceptance sign-offs.

Sign-offs form a directed graph where an edge A -> B means that sign-off A
defers its justification to sign-off B. A sign-off is only established when
its reference chain can reach material that independently covers the exact
artifact and version the sign-off was made against.

Three outcomes are distinguished:

* independently_supported - independent, correctly scoped material is
  attached to the sign-off itself or reachable through its references.
* evidence_incomplete - the chain ends without material and without a
  cycle; the evidence dossier is simply not complete yet.
* circular_reference - the chain is trapped in a reference cycle that
  carries no independent material itself.

The whole analysis works on the in-memory BOM model and never performs any
network access.
"""

from typing import Any, Optional

from .model import SignOff, SignOffEvaluation, SignOffStatus


class RiskAcceptanceAnalyzer:
    """Classify risk-acceptance sign-offs found in a BOM."""

    def evaluate(self, signoffs: list[SignOff]) -> list[SignOffEvaluation]:
        """Evaluate every sign-off and return one verdict per sign-off.

        Unknown risk:signoff:ref targets are treated as dangling edges:
        they can never provide support, but they do not create a cycle.
        """
        by_id = {item.signoff_id: item for item in signoffs}
        support_path = self._supporting_chains(signoffs, by_id)
        cyclic_nodes = self._cyclic_nodes(signoffs, by_id)
        evaluations: list[SignOffEvaluation] = []
        for signoff in signoffs:
            if signoff.signoff_id in support_path:
                chain = support_path[signoff.signoff_id]
                urls = self._supporting_urls(signoff, chain, by_id)
                evaluations.append(SignOffEvaluation(
                    signoff_id=signoff.signoff_id,
                    status=SignOffStatus.INDEPENDENTLY_SUPPORTED,
                    supporting_evidence=tuple(urls),
                    chain=tuple(chain),
                    reason=self._support_reason(chain),
                ))
            elif signoff.signoff_id in cyclic_nodes:
                evaluations.append(SignOffEvaluation(
                    signoff_id=signoff.signoff_id,
                    status=SignOffStatus.CIRCULAR_REFERENCE,
                    supporting_evidence=(),
                    chain=tuple(self._cycle_path(signoff, by_id)),
                    reason=self._cycle_reason(),
                ))
            else:
                evaluations.append(SignOffEvaluation(
                    signoff_id=signoff.signoff_id,
                    status=SignOffStatus.EVIDENCE_INCOMPLETE,
                    supporting_evidence=(),
                    chain=tuple(self._terminal_path(signoff, by_id)),
                    reason=self._incomplete_reason(),
                ))
        return evaluations

    def _supporting_chains(
        self,
        signoffs: list[SignOff],
        by_id: dict[str, SignOff],
    ) -> dict[str, list[str]]:
        """Map each supported node to one acyclic chain ending in material.

        Nodes carrying correctly scoped material themselves, or reaching
        such a node through references, get a chain. The chain never
        repeats a node: back edges are skipped during the DFS.
        """
        chains: dict[str, list[str]] = {}
        dead: set[str] = set()
        for root in signoffs:
            self._resolve_support(root.signoff_id, by_id, chains, dead)
        return chains

    def _resolve_support(
        self,
        start: str,
        by_id: dict[str, SignOff],
        chains: dict[str, list[str]],
        dead: set[str],
    ) -> None:
        if start in chains or start in dead:
            return
        if start not in by_id:
            dead.add(start)
            return
        stack: list[list[Any]] = [[start, 0]]
        trail = {start}
        while stack:
            frame = stack[-1]
            current = frame[0]
            if current in chains:
                self._unwind_supported(stack, chains)
                return
            current_node = by_id[current]
            if current_node.has_independent_material:
                chains[current] = [current]
                self._unwind_supported(stack, chains)
                return
            refs = current_node.references
            if frame[1] < len(refs):
                ref = refs[frame[1]]
                frame[1] += 1
                if ref in trail or ref in dead:
                    continue
                if ref not in by_id:
                    dead.add(ref)
                    continue
                trail.add(ref)
                stack.append([ref, 0])
            else:
                stack.pop()
                trail.discard(current)
                dead.add(current)

    @staticmethod
    def _unwind_supported(
        stack: list[list[Any]], chains: dict[str, list[str]]
    ) -> None:
        chain = chains[stack[-1][0]]
        stack.pop()
        while stack:
            ancestor = stack.pop()[0]
            chain = [ancestor, *chain]
            chains[ancestor] = chain

    def _cyclic_nodes(
        self,
        signoffs: list[SignOff],
        by_id: dict[str, SignOff],
    ) -> set[str]:
        """Return nodes whose only reachable justification is a cycle.

        Iterative Tarjan strongly connected components find the cycle
        members (multi-member SCCs or self referencing singletons). Nodes
        that merely lead into such a cycle are included as well, because
        their acceptance ultimately rests on circular reasoning.
        """
        index_counter = 0
        indices: dict[str, int] = {}
        lowlink: dict[str, int] = {}
        stack: list[str] = []
        on_stack: set[str] = set()
        cycle_members: set[str] = set()
        for root in (item.signoff_id for item in signoffs):
            if root in indices:
                continue
            work: list[list[Any]] = [[root, 0]]
            indices[root] = lowlink[root] = index_counter
            index_counter += 1
            stack.append(root)
            on_stack.add(root)
            while work:
                node, edge_pos = work[-1]
                refs = [r for r in by_id[node].references if r in by_id]
                if edge_pos < len(refs):
                    work[-1][1] = edge_pos + 1
                    successor = refs[edge_pos]
                    if successor not in indices:
                        indices[successor] = lowlink[successor] = index_counter
                        index_counter += 1
                        stack.append(successor)
                        on_stack.add(successor)
                        work.append([successor, 0])
                    elif successor in on_stack:
                        lowlink[node] = min(lowlink[node], indices[successor])
                else:
                    work.pop()
                    if work:
                        parent = work[-1][0]
                        lowlink[parent] = min(lowlink[parent], lowlink[node])
                    if lowlink[node] == indices[node]:
                        component: list[str] = []
                        while True:
                            member = stack.pop()
                            on_stack.discard(member)
                            component.append(member)
                            if member == node:
                                break
                        self_loop = (
                            len(component) == 1
                            and node in by_id[node].references
                        )
                        if len(component) > 1 or self_loop:
                            cycle_members.update(component)
        trapped: set[str] = set()

        def leads_to_cycle(node_id: str, seen: set[str]) -> bool:
            if node_id in trapped or node_id in cycle_members:
                return True
            if node_id in seen:
                return False
            seen.add(node_id)
            node = by_id.get(node_id)
            if node is None:
                return False
            return any(leads_to_cycle(r, seen) for r in node.references)

        for signoff in signoffs:
            if leads_to_cycle(signoff.signoff_id, set()):
                trapped.add(signoff.signoff_id)
        return trapped

    @staticmethod
    def _supporting_urls(
        signoff: SignOff,
        chain: list[str],
        by_id: dict[str, SignOff],
    ) -> list[str]:
        terminal = by_id[chain[-1]]
        return sorted(
            item.url for item in terminal.evidence
            if item.covers(signoff.artifact)
        )

    @staticmethod
    def _support_reason(chain: list[str]) -> str:
        if len(chain) == 1:
            return "independently scoped material is attached directly"
        return (
            f"material attached to {chain[-1]!r} is reachable through"
            f" the declared reference chain"
        )

    @staticmethod
    def _cycle_reason() -> str:
        return (
            "reference chain loops without any independently scoped"
            " material"
        )

    @staticmethod
    def _incomplete_reason() -> str:
        return (
            "reference chain ends before independent, artifact-scoped"
            " material is attached"
        )

    def _cycle_path(
        self, signoff: SignOff, by_id: dict[str, SignOff]
    ) -> list[str]:
        chain = [signoff.signoff_id]
        seen = {signoff.signoff_id}
        current: Optional[SignOff] = signoff
        while current is not None and current.references:
            ref = next((r for r in current.references if r in by_id), None)
            if ref is None:
                break
            chain.append(ref)
            if ref in seen:
                break
            seen.add(ref)
            current = by_id[ref]
        return chain

    def _terminal_path(
        self, signoff: SignOff, by_id: dict[str, SignOff]
    ) -> list[str]:
        chain = [signoff.signoff_id]
        seen = {signoff.signoff_id}
        current: Optional[SignOff] = signoff
        while current is not None and current.references:
            ref = current.references[0]
            chain.append(ref)
            if ref in seen:
                break
            seen.add(ref)
            current = by_id.get(ref)
        return chain
