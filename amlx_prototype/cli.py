import argparse

def __parseCliArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', action='count', default=0)
    subparsers = parser.add_subparsers(dest='cmd', required=True)
    parser.add_argument('-o', '--base', nargs=1, default=['bootstrap'], help='Default base name for all generated files', dest='base')
    parser.add_argument('--pki', nargs=1, default=None, help='Output dir to create the PKI files, overrides the OUTPUT_BASE if both are present.')

    bootstrapParser = subparsers.add_parser('bootstrap')
    bootstrapParser.add_argument('--test-fmus', nargs=1, default=None, help='Output dir to create the test AMLX instances')
    bootstrapParser.add_argument('--boilerplate-path', nargs=1, default=['boilerplate'], help='Path to look for the boilerplate files')
    bootstrapParser.add_argument('--output-inner-aml', action='store_true', help='Output the AML files as well for debugging')

    signingParser = subparsers.add_parser('sign')

    checkerParser = subparsers.add_parser('check')
    checkerParser.add_argument('file', nargs=1)
    checkerParser.add_argument('-r', '--root-cert', nargs=1, help='The root CA to look for')
    outputGroup = checkerParser.add_mutually_exclusive_group(required=True)
    outputGroup.add_argument('-o', '--output', nargs=1, help='If given, store the extracted FMU in a file for use in legacy apps.')
    outputGroup.add_argument('--test-only', action='store_true', help='Do not export the FMU but only check the validity and output a message.')
    modeGroup = checkerParser.add_mutually_exclusive_group()
    modeGroup.add_argument('--only-hash', action='store_true', help='Do not check the signature but only the hash')
    modeGroup.add_argument('--ignore-hash', action='store_true', help='Do not check the hash within the AMLX container')
    checkerParser.add_argument('--force', action='store_true', help='Run all tests even if some fail.')

    args = parser.parse_args()

    return args

args = __parseCliArgs()
