import argparse
from mako.template import Template

parser = argparse.ArgumentParser(
                    prog='Template',
                    description='Template database creation script')

parser.add_argument('filepath', type=str,
                    help='path of file to template')

parser.add_argument('password_1', type=str,
                    help='password of user gardener_1')

parser.add_argument('password_2', type=str,
                    help='password of user gardener_2')

args = parser.parse_args()

mytemplate = Template(filename=args.filepath)

print(mytemplate.render(password_1=args.password_1, password_2=args.password_2))

