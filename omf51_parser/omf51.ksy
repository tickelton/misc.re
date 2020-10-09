meta:
  id: omf51
  file-extension: lib
  endian: le
instances:
  object_type:
    pos: 0x0
    type: u1
seq:
  - id: omf51_library
    type: omf51_library
    if: object_type == 0x2c
  - id: om51_module
    type: omf51_module
    repeat: eos
    if: object_type == 0x02
types:
  omf51_string:
    seq:
      - id: string_length
        type: u1
      - id: string_data
        type: str
        size: string_length
        encoding: UTF-8
  omf51_module_location:
    seq:
      - id: block_number
        type: u2
      - id: byte_number
        type: u2
  library_header_record:
    seq:
      - id: record_type
        contents: [0x2c]
      - id: record_length
        type: u2
      - id: module_count
        type: u2
      - id: block_number
        type: u2
      - id: byte_number
        type: u2
      - id: chk_sum
        type: u1
  library_module_names_record:
    seq:
      - id: record_type
        contents: [0x28]
      - id: record_length
        type: u2
      - id: module_names
        type: library_module_names_record_data
        size: record_length - 1
      - id: chk_sum
        type: u1
  library_module_names_record_data:
    seq:
      - id: module_name
        type: omf51_string
        repeat: eos
  library_module_locations_record:
    seq:
      - id: record_type
        contents: [0x26]
      - id: record_length
        type: u2
      - id: module_locations
        type: library_module_locations_record_data
        size: record_length - 1
      - id: chk_sum
        type: u1
  library_module_locations_record_data:
    seq:
      - id: module_location
        type: omf51_module_location
        repeat: eos
  library_dictionary_record:
    seq:
      - id: record_type
        contents: [0x2a]
      - id: record_length
        type: u2
      - id: library_dictionary_record_data
        type: library_dictionary_record_data
        size: record_length - 1
      - id: chk_sum
        type: u1
  library_dictionary_record_data:
    seq:
      - id: public_names
        type: public_names_data
        terminator: 0
        repeat: eos
  public_names_data:
    seq:
      - id: public_names_data_body
        type: omf51_string
        repeat: eos
  omf51_library:
    seq:
      - id: library_header
        type: library_header_record
      - id: module
        type: omf51_module
        repeat: expr
        repeat-expr: library_header.module_count
#      - id: library_module_names
#        type: library_module_names_record
#      - id: library_module_locations
#        type: library_module_locations_record
#      - id: library_dictionary
#        type: library_dictionary_record
  module_header_record:
    seq:
      - id: record_type
        type: u1
        #contents: [0x02]
      - id: record_length
        type: u2
      - id: module_name
        type: omf51_string
      - id: trn_id
        type: u1
      - id: reserved
        type: u1
      - id: chk_sum
        type: u1
  module_end_record:
    seq:
#      - id: record_type
#        type: u1
#        contents: [0x04]
      - id: record_length
        type: u2
      - id: module_name
        type: omf51_string
      - id: reserved1
        type: u2
      - id: reg_mask
        type: u1
      - id: reserved2
        type: u1
      - id: chk_sum
        type: u1
  segment_definition_type:
    params:
      - id: id_extended
        type: bool
    seq:
      - id: seg_id
        type: u1
        if: id_extended == false
      - id: seg_id_ext
        type: u2
        if: id_extended == true
      - id: seg_info
        type: u1
      - id: rel_type
        type: u1
      - id: reserved
        type: u1
      - id: segment_base
        type: u2
      - id: segment_size
        type: u2
      - id: segment_name
        type: omf51_string
  segment_definitions_data:
    params:
      - id: id_extended
        type: bool
    seq:
      - id: segment_definition
        type: segment_definition_type(id_extended)
        repeat: eos
  segment_definitions_record:
    params:
      - id: id_extended
        type: bool
    seq:
      - id: record_length
        type: u2
      - id: segment_definitions
        type: segment_definitions_data(id_extended)
        size: record_length - 1
      - id: chk_sum
        type: u1
  module_body_record:
    seq:
      - id: record_type
        type: u1
        enum: module_body_record_types
      - id: module_body_data
        type:
          switch-on: record_type
          cases:
            module_body_record_types::module_end: module_end_record
            #module_body_record_types::segment_definition: segment_definitions_record(false)
            module_body_record_types::segment_definition_extended: segment_definitions_record(true)
            _: u1
  omf51_module:
    seq:
      - id: module_header
        type: module_header_record
      - id: module_body
        type: module_body_record
        repeat: until
        repeat-until: _.record_type == module_body_record_types::module_end
enums:
  module_body_record_types:
    0x04: module_end
    0x0e: segment_definition
    0x0f: segment_definition_extended


