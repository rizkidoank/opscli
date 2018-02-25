from opscli.parser import create_parser


def main():
    parser = create_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except Exception as e:
        print(e)


if __name__ == '__main__':
    main()
