# Conversion to aiopacketstrider updates

1. Implementation of Asyncio for performance
2. Reformatting of source according to PEP8 (largely done via Black default settings)
3. Conversion of strings to leverage Py3.6+ F-Strings where applicable
4. Introduction of Type-hinting/Static Typing according to PEP484
5. Reorganization into Python Package with Modules

## Future Considerations

1. Swap out PyShark for a potentially more performant lib such as dpkt or scapy (how much performance can be gained
 is questionable given a parsing module for SSH will have to be written on-top of those libraries)