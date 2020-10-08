meta:
  id: omf51
  file-extension: lib
  endian: le
instances:
  object_type:
    pos: 0x0
    type: u1
seq:
  - id: omf51_data
    type:
      switch-on: object_type
      cases:
        0x2c: omf51_library
        0x02: omf51_module
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
        type: u1
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
        type: u1
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
        type: u1
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
        type: u1
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
      - id: temp_garbage
        size: 87734
      - id: library_module_names
        type: library_module_names_record
      - id: library_module_locations
        type: library_module_locations_record
      - id: library_dictionary
        type: library_dictionary_record
  omf51_module:
    seq:
      - id: garbage
        type: u1
        repeat: eos
