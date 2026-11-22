import struct
from dataclasses import dataclass


PRIMITIVE_ENCODE = {
    'System.Void': 0x01,
    'System.Boolean': 0x02,
    'System.Char': 0x03,
    'System.SByte': 0x04,
    'System.Byte': 0x05,
    'System.Int16': 0x06,
    'System.UInt16': 0x07,
    'System.Int32': 0x08,
    'System.UInt32': 0x09,
    'System.Int64': 0x0A,
    'System.UInt64': 0x0B,
    'System.Single': 0x0C,
    'System.Double': 0x0D,
    'System.String': 0x0E,
    'System.TypedReference': 0x16,
    'System.IntPtr': 0x18,
    'System.UIntPtr': 0x19,
    'System.Object': 0x1C,
}

VISIBILITY = {
    'public': 0x6,
    'private': 0x1,
    'protected': 0x4,
    'internal': 0x3,
    'private_protected': 0x2,
    'protected_internal': 0x5,
}

TYPE_VISIBILITY = {
    'public': 0x1,
    'nested_public': 0x2,
    'nested_private': 0x3,
    'nested_protected': 0x4,
    'nested_internal': 0x5,
    'nested_private_protected': 0x6,
    'nested_protected_internal': 0x7,
    'internal': 0x0,
}


def _u16(value):
    return struct.pack('<H', value)


def _u32(value):
    return struct.pack('<I', value)


def _align(value, alignment):
    return (value + alignment - 1) // alignment * alignment


def _compressed(value):
    if value <= 0x7F:
        return bytes([value])
    if value <= 0x3FFF:
        return bytes([0x80 | (value >> 8), value & 0xFF])
    if value <= 0x1FFFFFFF:
        return bytes([0xC0 | (value >> 24), (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF])
    raise ValueError('compressed integer too large')


@dataclass
class TypeHandle:
    assembly: 'SyntheticAssembly'
    rid: int
    namespace: str
    name: str
    full_name: str


class SyntheticAssembly:
    def __init__(self, name, version=(1, 0, 0, 0)):
        self.name = name
        self.version = version
        self.string_heap = bytearray(b'\x00')
        self.string_cache = {'': 0}
        self.blob_heap = bytearray(b'\x00')
        self.blob_cache = {}
        self.guid_heap = bytearray(b'\x00' * 16)
        self.assembly_refs = []
        self.assembly_ref_names = {}
        self.typerefs = []
        self.typeref_names = {}
        self.types = []
        self.type_names = {}
        self.typespecs = []
        self.property_rows = []
        self.event_rows = []
        self.property_maps = []
        self.event_maps = []
        self.method_semantics = []
        self.nested_rows = []
        self._add_type('<Module>', '', extends=None, visibility='internal', module=True)

    def string(self, value):
        value = value or ''
        if value in self.string_cache:
            return self.string_cache[value]
        index = len(self.string_heap)
        self.string_heap.extend(value.encode('utf-8') + b'\x00')
        self.string_cache[value] = index
        return index

    def blob(self, data):
        data = bytes(data)
        if data in self.blob_cache:
            return self.blob_cache[data]
        index = len(self.blob_heap)
        self.blob_heap.extend(_compressed(len(data)) + data)
        self.blob_cache[data] = index
        return index

    def assembly_ref(self, name):
        if name in self.assembly_ref_names:
            return self.assembly_ref_names[name]
        self.assembly_refs.append(name)
        rid = len(self.assembly_refs)
        self.assembly_ref_names[name] = rid
        return rid

    def typeref(self, assembly, namespace, name):
        key = (assembly, namespace, name)
        if key in self.typeref_names:
            return self.typeref_names[key]
        self.assembly_ref(assembly)
        self.typerefs.append({'assembly': assembly, 'namespace': namespace, 'name': name})
        rid = len(self.typerefs)
        self.typeref_names[key] = rid
        return rid

    def _add_type(self, name, namespace, extends, visibility, module=False):
        full_name = namespace + '.' + name if namespace and not module else name
        record = {
            'namespace': namespace,
            'name': name,
            'full_name': full_name,
            'extends': extends,
            'visibility': visibility,
            'is_interface': False,
            'flags_extra': 0,
            'fields': [],
            'methods': [],
            'interfaces': [],
            'enclosing': None,
        }
        self.types.append(record)
        rid = len(self.types)
        if not module:
            self.type_names[full_name] = rid
            self.type_names[full_name.replace('+', '.')] = rid
        record['rid'] = rid
        return record

    def add_type(self, namespace, name, extends=None, visibility='public', is_interface=False,
                 flags=0, interfaces=()):
        if extends is None and not is_interface:
            extends = '[mscorlib]System.Object'
        if is_interface:
            flags |= 0x20
        record = self._add_type(name, namespace, extends, visibility)
        record['is_interface'] = is_interface
        record['flags_extra'] = flags
        for item in interfaces:
            record['interfaces'].append(item)
        return TypeHandle(self, record['rid'], namespace, name, record['full_name'])

    def add_nested_type(self, enclosing, name, visibility='nested_public', is_interface=False, flags=0):
        parent = self.types[enclosing.rid - 1]
        record = self._add_type(name, '', None, visibility)
        record['full_name'] = parent['full_name'] + '+' + name
        record['enclosing'] = enclosing.rid
        record['is_interface'] = is_interface
        record['flags_extra'] = flags | (0x20 if is_interface else 0)
        self.type_names[record['full_name']] = record['rid']
        self.type_names[record['full_name'].replace('+', '.')] = record['rid']
        self.nested_rows.append((record['rid'], enclosing.rid))
        return TypeHandle(self, record['rid'], '', name, record['full_name'])

    def add_interface(self, namespace, name):
        return self.add_type(namespace, name, extends=None, is_interface=True)

    def implement(self, owner, interface):
        self.types[owner.rid - 1]['interfaces'].append(interface)

    def _local_type(self, spec):
        if isinstance(spec, TypeHandle):
            return spec.rid
        if isinstance(spec, int):
            return spec
        if spec in self.type_names:
            return self.type_names[spec]
        return None

    def _external_type(self, spec):
        if not isinstance(spec, str):
            return None
        text = spec.strip()
        if not (text.startswith('[') and ']' in text):
            return None
        assembly, rest = text[1:].split(']', 1)
        if '.' in rest:
            namespace, name = rest.rsplit('.', 1)
        else:
            namespace, name = '', rest
        return self.typeref(assembly, namespace, name)

    def type_def_or_ref(self, spec):
        local = self._local_type(spec)
        if local is not None:
            return (local << 2) | 0
        external = self._external_type(spec)
        if external is not None:
            return (external << 2) | 1
        raise ValueError('unknown type reference: %r' % (spec,))

    def encode_type(self, spec, allow_void=True):
        if spec is None:
            return bytes([0x1C])
        if isinstance(spec, tuple) and spec and spec[0] == 'generic':
            base = spec[1]
            args = spec[2]
            out = bytes([0x15, 0x12]) + _compressed(self.type_def_or_ref(base))
            out += _compressed(len(args))
            for arg in args:
                out += self.encode_type(arg)
            return out
        if isinstance(spec, TypeHandle) or isinstance(spec, int):
            return bytes([0x12]) + _compressed(self.type_def_or_ref(spec))
        if spec in PRIMITIVE_ENCODE:
            return bytes([PRIMITIVE_ENCODE[spec]])
        text = str(spec).strip()
        if text.endswith('[]'):
            return bytes([0x1D]) + self.encode_type(text[:-2])
        if text.endswith('&'):
            return bytes([0x10]) + self.encode_type(text[:-1])
        if text.endswith('*'):
            return bytes([0x0F]) + self.encode_type(text[:-1])
        if text.startswith('['):
            return bytes([0x12]) + _compressed(self.type_def_or_ref(text))
        local = self._local_type(text)
        if local is not None:
            return bytes([0x12]) + _compressed((local << 2) | 0)
        raise ValueError('unknown type reference: %r' % (spec,))

    def add_method(self, owner, name, return_type='System.Void', params=(), visibility='public',
                   static=False, generic_params=0, virtual=False, special=False, abstract=False):
        flags = VISIBILITY[visibility]
        if static:
            flags |= 0x10
        if virtual:
            flags |= 0x40
        if special:
            flags |= 0x800
        if abstract:
            flags |= 0x400
        if name in ('.ctor', '.cctor'):
            flags |= 0x1800
        callconv = (0x00 if static else 0x20) | (0x10 if generic_params else 0)
        sig = bytes([callconv])
        if generic_params:
            sig += _compressed(generic_params)
        sig += _compressed(len(params))
        sig += self.encode_type(return_type)
        for param in params:
            sig += self.encode_type(param)
        record = {
            'owner': owner.rid,
            'name': name,
            'flags': flags,
            'signature': self.blob(sig),
            'param_names': ['arg%d' % (i + 1) for i in range(len(params))],
        }
        self.types[owner.rid - 1]['methods'].append(record)
        return record

    def add_field(self, owner, name, field_type, visibility='public', static=False, initonly=False, literal=False):
        flags = VISIBILITY[visibility]
        if static:
            flags |= 0x10
        if initonly:
            flags |= 0x20
        if literal:
            flags |= 0x40
        sig = bytes([0x06]) + self.encode_type(field_type)
        record = {
            'owner': owner.rid,
            'name': name,
            'flags': flags,
            'signature': self.blob(sig),
        }
        self.types[owner.rid - 1]['fields'].append(record)
        return record

    def add_property(self, owner, name, return_type, params=(), getter=True, setter=False,
                     getter_visibility='public', setter_visibility='public', static=False):
        callconv = 0x08 | (0x00 if static else 0x20)
        sig = bytes([callconv]) + _compressed(len(params)) + self.encode_type(return_type)
        for param in params:
            sig += self.encode_type(param)
        prop_index = len(self.property_rows) + 1
        self.property_rows.append({
            'name': name,
            'flags': 0,
            'signature': self.blob(sig),
            'accessors': [],
        })
        self.property_maps.append((owner.rid, prop_index))
        accessors = []
        if getter:
            method = self.add_method(owner, 'get_' + name, return_type, params,
                                     visibility=getter_visibility, static=static, special=True)
            accessors.append(('get', method))
        if setter:
            method = self.add_method(owner, 'set_' + name, 'System.Void', tuple(params) + (return_type,),
                                     visibility=setter_visibility, static=static, special=True)
            accessors.append(('set', method))
        self.property_rows[prop_index - 1]['accessors'] = accessors
        return prop_index

    def add_event(self, owner, name, event_type, add=True, remove=True,
                  access_visibility='public', static=False):
        event_index = len(self.event_rows) + 1
        self.event_rows.append({'name': name, 'flags': 0, 'type': event_type, 'accessors': []})
        self.event_maps.append((owner.rid, event_index))
        accessors = []
        handler = event_type
        if add:
            method = self.add_method(owner, 'add_' + name, 'System.Void', (handler,),
                                     visibility=access_visibility, static=static, special=True)
            accessors.append(('add', method))
        if remove:
            method = self.add_method(owner, 'remove_' + name, 'System.Void', (handler,),
                                     visibility=access_visibility, static=static, special=True)
            accessors.append(('remove', method))
        self.event_rows[event_index - 1]['accessors'] = accessors
        return event_index

    def _ordered_fields(self):
        result = []
        for type_record in self.types:
            result.extend(type_record['fields'])
        return result

    def _ordered_methods(self):
        result = []
        for type_record in self.types:
            result.extend(type_record['methods'])
        return result

    def build(self):
        # Resolve all coded references before emitting the TypeRef table; the
        # table rows must be complete before any row that indexes them.
        for type_record in self.types:
            if type_record['extends'] is not None:
                self.type_def_or_ref(type_record['extends'])
            for interface in type_record['interfaces']:
                self.type_def_or_ref(interface)
        for item in self.event_rows:
            self.type_def_or_ref(item['type'])

        ordered_fields = self._ordered_fields()
        ordered_methods = self._ordered_methods()
        field_rid = {id(item): index + 1 for index, item in enumerate(ordered_fields)}
        method_rid = {id(item): index + 1 for index, item in enumerate(ordered_methods)}

        field_starts = {}
        method_starts = {}
        cursor = 1
        for type_record in self.types:
            field_starts[type_record['rid']] = cursor
            cursor += len(type_record['fields'])
        cursor = 1
        for type_record in self.types:
            method_starts[type_record['rid']] = cursor
            cursor += len(type_record['methods'])

        param_rows = []
        param_starts = {}
        for method in ordered_methods:
            param_starts[id(method)] = len(param_rows) + 1
            for index, param_name in enumerate(method['param_names']):
                param_rows.append({'flags': 0, 'sequence': index + 1, 'name': param_name})

        for formula in self.property_rows + self.event_rows:
            for accessor_name, method in formula['accessors']:
                self.method_semantics.append({
                    'semantics': {'get': 0x0002, 'set': 0x0001, 'add': 0x0008, 'remove': 0x0010}[accessor_name],
                    'method': method_rid[id(method)],
                    'association_kind': 'property' if formula in self.property_rows else 'event',
                    'association_rid': (self.property_rows.index(formula) + 1) if formula in self.property_rows else (self.event_rows.index(formula) + 1),
                })

        rows = {}

        module_name = self.name + '.dll'
        rows[0] = _u16(0) + _u16(self.string(module_name)) + _u16(1) + _u16(0) + _u16(0)

        typeref_rows = []
        for item in self.typerefs:
            ref_rid = self.assembly_ref_names[item['assembly']]
            scope = (ref_rid << 2) | 2
            typeref_rows.append(_u16(scope) + _u16(self.string(item['name'])) + _u16(self.string(item['namespace'])))
        rows[1] = b''.join(typeref_rows)

        typedef_rows = []
        for type_record in self.types:
            if type_record['rid'] == 1:
                flags = 0
                namespace = ''
                name = '<Module>'
                extends = 0
            else:
                visibility_key = type_record['visibility']
                flags = TYPE_VISIBILITY[visibility_key] | type_record['flags_extra']
                namespace = type_record['namespace']
                name = type_record['name']
                extends = 0 if type_record['extends'] is None else self.type_def_or_ref(type_record['extends'])
            typedef_rows.append(
                _u32(flags) + _u16(self.string(name)) + _u16(self.string(namespace)) +
                _u16(extends) + _u16(field_starts[type_record['rid']]) + _u16(method_starts[type_record['rid']])
            )
        rows[2] = b''.join(typedef_rows)

        field_rows = []
        for item in ordered_fields:
            field_rows.append(_u16(item['flags']) + _u16(self.string(item['name'])) + _u16(item['signature']))
        rows[4] = b''.join(field_rows)

        method_rows = []
        for item in ordered_methods:
            method_rows.append(
                _u32(0) + _u16(0) + _u16(item['flags']) + _u16(self.string(item['name'])) +
                _u16(item['signature']) + _u16(param_starts[id(item)])
            )
        rows[6] = b''.join(method_rows)

        param_table = []
        for item in param_rows:
            param_table.append(_u16(item['flags']) + _u16(item['sequence']) + _u16(self.string(item['name'])))
        rows[8] = b''.join(param_table)

        interface_rows = []
        for type_record in self.types:
            for interface in type_record['interfaces']:
                interface_rows.append(_u16(type_record['rid']) + _u16(self.type_def_or_ref(interface)))
        rows[9] = b''.join(interface_rows)

        property_maps = []
        for owner_rid, prop_rid in self.property_maps:
            property_maps.append(_u16(owner_rid) + _u16(prop_rid))
        rows[21] = b''.join(property_maps)

        property_table = []
        for item in self.property_rows:
            property_table.append(_u16(item['flags']) + _u16(self.string(item['name'])) + _u16(item['signature']))
        rows[23] = b''.join(property_table)

        event_maps = []
        for owner_rid, event_rid in self.event_maps:
            event_maps.append(_u16(owner_rid) + _u16(event_rid))
        rows[18] = b''.join(event_maps)

        event_table = []
        for item in self.event_rows:
            event_table.append(_u16(item['flags']) + _u16(self.string(item['name'])) + _u16(self.type_def_or_ref(item['type'])))
        rows[20] = b''.join(event_table)

        semantics_rows = []
        for item in self.method_semantics:
            tag = 0 if item['association_kind'] == 'event' else 1
            association = (item['association_rid'] << 1) | tag
            semantics_rows.append(_u16(item['semantics']) + _u16(item['method']) + _u16(association))
        rows[24] = b''.join(semantics_rows)

        typespec_rows = []
        for item in self.typespecs:
            typespec_rows.append(_u16(item))
        rows[27] = b''.join(typespec_rows)

        assembly_row = (
            _u32(0x8004) + _u16(self.version[0]) + _u16(self.version[1]) + _u16(self.version[2]) + _u16(self.version[3]) +
            _u32(0) + _u16(0) + _u16(self.string(self.name)) + _u16(0)
        )
        rows[32] = assembly_row

        assembly_ref_rows = []
        for ref_name in self.assembly_refs:
            assembly_ref_rows.append(
                _u16(4) + _u16(0) + _u16(0) + _u16(0) + _u32(0) + _u16(0) +
                _u16(self.string(ref_name)) + _u16(0) + _u16(0)
            )
        rows[35] = b''.join(assembly_ref_rows)

        nested_rows = []
        for nested, enclosing in self.nested_rows:
            nested_rows.append(_u16(nested) + _u16(enclosing))
        rows[41] = b''.join(nested_rows)

        mask = 0
        for number, data in rows.items():
            if data:
                mask |= 1 << number
        row_counts = []
        table_data = b''
        for number in range(64):
            if mask & (1 << number):
                data = rows.get(number, b'')
                count = 0
                if number == 0:
                    count = 1
                elif number == 1:
                    count = len(self.typerefs)
                elif number == 2:
                    count = len(self.types)
                elif number == 4:
                    count = len(ordered_fields)
                elif number == 6:
                    count = len(ordered_methods)
                elif number == 8:
                    count = len(param_rows)
                elif number == 9:
                    count = len(interface_rows)
                elif number == 18:
                    count = len(event_maps)
                elif number == 20:
                    count = len(event_table)
                elif number == 21:
                    count = len(property_maps)
                elif number == 23:
                    count = len(property_table)
                elif number == 24:
                    count = len(semantics_rows)
                elif number == 27:
                    count = len(typespec_rows)
                elif number == 32:
                    count = 1
                elif number == 35:
                    count = len(self.assembly_refs)
                elif number == 41:
                    count = len(nested_rows)
                row_counts.append(_u32(count))
                table_data += data

        header = _u32(0) + bytes([2, 0, 0, 1]) + struct.pack('<Q', mask) + struct.pack('<Q', 0)
        tables_stream = header + b''.join(row_counts) + table_data
        while len(tables_stream) % 4:
            tables_stream += b'\x00'

        strings_stream = bytes(self.string_heap)
        blob_stream = bytes(self.blob_heap)
        guid_stream = bytes(self.guid_heap)
        for value in (strings_stream, blob_stream, guid_stream):
            while len(value) % 4:
                value += b'\x00'

        streams = [
            (b'#~', tables_stream),
            (b'#Strings', strings_stream),
            (b'#GUID', guid_stream),
            (b'#Blob', blob_stream),
        ]
        version = b'v4.0.30319\x00\x00'
        root = struct.pack('<IHHII', 0x424A5342, 1, 1, 0, len(version)) + version
        root += _u16(0) + _u16(len(streams))
        headers_size = 0
        for name, data in streams:
            padded_name = name + b'\x00'
            while len(padded_name) % 4:
                padded_name += b'\x00'
            headers_size += 8 + len(padded_name)
        offset = len(root) + headers_size
        stream_headers = b''
        stream_payload = b''
        for name, data in streams:
            padded_name = name + b'\x00'
            while len(padded_name) % 4:
                padded_name += b'\x00'
            stream_headers += _u32(offset) + _u32(len(data)) + padded_name
            stream_payload += data
            offset += len(data)
        metadata = root + stream_headers + stream_payload
        while len(metadata) % 4:
            metadata += b'\x00'

        clr = struct.pack(
            '<IHHIIIIIIIIIIIIIIII',
            72, 2, 5, 0x2000 + 72, len(metadata), 1, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        )
        section_data = clr + metadata
        virtual_size = len(section_data)
        raw_size = _align(virtual_size, 0x200)
        section_data += b'\x00' * (raw_size - len(section_data))

        headers = bytearray(0x200)
        headers[0:2] = b'MZ'
        struct.pack_into('<I', headers, 0x3C, 0x80)
        headers[0x80:0x84] = b'PE\x00\x00'
        struct.pack_into('<HHIIIHH', headers, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x2102)
        opt = 0x98
        struct.pack_into('<HBBIIIIII', headers, opt, 0x10B, 8, 0, raw_size, 0, 0, 0, 0x2000, 0x2000)
        struct.pack_into(
            '<IIIHHHHHHIIIIHHIIIIII',
            headers, opt + 28,
            0x400000, 0x2000, 0x200, 4, 0, 0, 0, 4, 0, 0,
            0x2000 + _align(virtual_size, 0x2000), 0x200, 0, 3, 0,
            0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
        )
        struct.pack_into('<II', headers, opt + 96 + 14 * 8, 0x2000, 72)
        section_header = 0x178
        headers[section_header:section_header + 8] = b'.text\x00\x00\x00'
        struct.pack_into('<IIIIIIHHI', headers, section_header + 8, virtual_size, 0x2000, raw_size, 0x200, 0, 0, 0, 0, 0x60000020)

        return bytes(headers) + section_data
