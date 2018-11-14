import os
import argparse


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('-n', '--number', type=int, default=100,
                        help="determine the number of generation password")

    parser.add_argument('-p', '--pattern', type=str, default='s',
                        help="choose the string of the generation pattern including 's': structure, 'k': keyboard, \
                        'd': date, 'w': words, 'a': all pattern combination")

    args = parser.parse_args()

    number = args.number
    pattern = args.pattern

    if pattern == 's':
        os.system("python .\\structure\\codeAndReadme\\PassWdTotal.py")
        os.system("python .\\structure\\codeAndReadme\\mxm_structure.py " + str(number))
    elif pattern == 'k':
        os.system("python .\\keyboard\\keyboard_analyse.py " + str(number))
    elif pattern == 'd':
        os.system("python .\\date\\DKA.py " + str(number))
    elif pattern == 'w':
        os.system("python .\\word\\csdn\\csdn_englishword_anaysis.py " + str(number))
        os.system("python .\\word\\yahoo\\yahoo_englishword_analysis.py " + str(number))
    elif pattern == 'a':
        os.system("python .\\structure\\codeAndReadme\\PassWdTotal.py")
        os.system("python .\\structure\\codeAndReadme\\mxm_structure.py " + str(number))

        os.system("python .\\keyboard\\keyboard_analyse.py " + str(number))

        os.system("python .\\date\\DKA.py " + str(number))

        os.system("python .\\word\\csdn\\csdn_englishword_anaysis.py " + str(number))
        os.system("python .\\word\\yahoo\\yahoo_englishword_analysis.py " + str(number))

    print("> Generation complete")