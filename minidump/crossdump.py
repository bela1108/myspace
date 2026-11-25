"""Align evidence collected from two minidumps."""

from datetime import datetime, timezone

from minidump.minidumpfile import MinidumpFile


class CrossDumpAlignment:
	def __init__(self, first_dump, second_dump):
		self.first_dump = first_dump
		self.second_dump = second_dump
		self.common_facts = []
		self.conflict_facts = []
		self.first_only_facts = []
		self.second_only_facts = []

	def to_dict(self):
		return {
			'dumps': {
				'first': dump_summary(self.first_dump),
				'second': dump_summary(self.second_dump),
			},
			'common_facts': self.common_facts,
			'conflict_facts': self.conflict_facts,
			'first_only_facts': self.first_only_facts,
			'second_only_facts': self.second_only_facts,
		}

	def __str__(self):
		return format_alignment_text(self)

