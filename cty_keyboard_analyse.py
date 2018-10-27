

def read_csdn_data(passwd_file):
    user_list = []
    passwd_list = []
    mail_list = []

    print("Reading csdn data...")
    f = open(passwd_file, 'r', encoding="ISO-8859-1")
    for line in f:
        user_list.append(line.split(" # ")[0])
        passwd_list.append(line.split(" # ")[1])
        mail_list.append(line.split(" # ")[2][:-1])
    f.close()
    # print(user_list[0], passwd_list[0], mail_list[0])

    return user_list, passwd_list, mail_list


def read_yahoo_data(passwd_file):
    mail_list = []
    passwd_list = []

    print("Reading yahoo data...")
    line_count = 0
    f = open(passwd_file, 'r', encoding="ISO-8859-1")
    for line in f:
        line_count += 1
        # if 3073 <= line_count <= 456564:
        if len(line.split(":")) == 3:
            mail_list.append(line.split(":")[1])
            passwd_list.append(line.split(":")[2][:-1])
    f.close()
    # print(passwd_list[0], mail_list[0])

    return passwd_list, mail_list


def LCS(pattern, passwd):
    dp = [[0 for j in range(len(pattern) + 1)] for i in range(len(passwd) + 1)]
    # print(dp)

    for i in range(1, len(passwd) + 1):
        for j in range(1, len(pattern) + 1):
            dp[i][j] = 0
            # print(i,j)
            if passwd[i-1] == pattern[j-1]:
                dp[i][j] = dp[i-1][j-1] + 1

    # for i in range(1, len(passwd) + 1):
    #     print(dp[i][1:])

    longest_len = -1
    string_end = -1
    for i in range(1, len(passwd) + 1):
        for j in range(1, len(pattern) + 1):
            if longest_len < dp[i][j]:
                longest_len = dp[i][j]
                string_end = i

    longest_common_strng = passwd[string_end - longest_len:string_end]
    # print(pattern, passwd, longest_common_strng)

    return longest_len, longest_common_strng


def keyboard_hobby_analyse(passwd, result_filename):

    # match mode in pattern:
    # 0-3 first keyboard line
    # 4-7 second keyboard line
    # 8-11 third keyboard line
    # 12-15 fourth keyboard line
    # 16-19 left little finger
    # 20-23 left ring finger
    # 24-27 left middle finger
    # 28-31 left index finger
    # 32-35 right index finger
    # 36-39 right middle finger
    # 40-43 right ring finger
    # 44-47 right little finger
    # 48-53 little keyboard
    # 54-57 26 English characters

    pattern = [
        "`1234567890-=",
        "=-0987654321`",
        "~!@#$%^&*()_+",
        "+_)(*&^%$#@!~",

        "qwertyuiop[]\\",
        "\\][poiuytrewq",
        "QWERTYUIOP{}|",
        "|}{POIUYTREWQ",

        "asdfghjkl;\'",
        "\';lkjhgfdsa",
        "ASDFGHJKL:\"",
        "\":LKJHGFDSA",

        "zxcvbnm,./",
        "/.,mnbvcxz",
        "ZXCVBNM<>?",
        "?><MNBVCXZ",

        "`1qaz",
        "zaq1`",
        "~!QAZ",
        "ZAQ!~",
        
        "2wsx",
        "xsw2",
        "@WSX",
        "XSW@",

        "3edc",
        "cde3",
        "#EDC",
        "CDE#",

        "4rfv5tgb",
        "bgt5vfr4",
        "$RFV%TGB",
        "BGT%VFR$",

        "6yhn7ujm",
        "mju7nhy6",
        "^YHN&UJM",
        "MJU&NHY^",

        "8ik,",
        ",ki8",
        "*IK<",
        "<KI*",

        "9ol.",
        ".lo9",
        "(OL>",
        ">LO(",

        "0p;/-['=]\\",
        "\\]='[-/;p0",
        ")P:?_{\"+}|",
        "|}+\"{_?:P)",
        
        "0147",
        "7410",
        "0258",
        "8520",
        ".369",
        "963.",

        "abcdefghijklmnopqrstuvwxyz",
        "zyxwvutsrqponmlkjihgfedcba",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "ZYXWVUTSRQPONMLKJIHGFEDCBA"
    ]

    print("Keyboard hobby analyse...")
    keyword_dict = {
        "first keyboard line": {},
        "second keyboard line": {},
        "third keyboard line": {},
        "fourth keyboard line": {},
        "left little finger": {},
        "left ring finger": {},
        "left middle finger": {},
        "left index finger": {},
        "right index finger": {},
        "right middle finger": {},
        "right ring finger": {},
        "right little finger": {},
        "little keyboard": {},
        "26 English characters": {}
    }
    for mode_number in range(0, len(pattern)):
        print("mode %s analyse..." % mode_number)
        for passwd_element in passwd:
            longest_len, longest_common_string = LCS(pattern[mode_number], passwd_element)
            if longest_len >= 3:
                if 0 <= mode_number <= 3:
                    if longest_common_string in keyword_dict["first keyboard line"].keys():
                        keyword_dict["first keyboard line"][longest_common_string] += 1
                    else:
                        keyword_dict["first keyboard line"][longest_common_string] = 1
                elif 4 <= mode_number <= 7:
                    if longest_common_string in keyword_dict["second keyboard line"].keys():
                        keyword_dict["second keyboard line"][longest_common_string] += 1
                    else:
                        keyword_dict["second keyboard line"][longest_common_string] = 1
                elif 8 <= mode_number <= 11:
                    if longest_common_string in keyword_dict["third keyboard line"].keys():
                        keyword_dict["third keyboard line"][longest_common_string] += 1
                    else:
                        keyword_dict["third keyboard line"][longest_common_string] = 1
                elif 12 <= mode_number <= 15:
                    if longest_common_string in keyword_dict["fourth keyboard line"].keys():
                        keyword_dict["fourth keyboard line"][longest_common_string] += 1
                    else:
                        keyword_dict["fourth keyboard line"][longest_common_string] = 1
                elif 16 <= mode_number <= 19:
                    if longest_common_string in keyword_dict["left little finger"].keys():
                        keyword_dict["left little finger"][longest_common_string] += 1
                    else:
                        keyword_dict["left little finger"][longest_common_string] = 1
                elif 20 <= mode_number <= 23:
                    if longest_common_string in keyword_dict["left ring finger"].keys():
                        keyword_dict["left ring finger"][longest_common_string] += 1
                    else:
                        keyword_dict["left ring finger"][longest_common_string] = 1
                elif 24 <= mode_number <= 27:
                    if longest_common_string in keyword_dict["left middle finger"].keys():
                        keyword_dict["left middle finger"][longest_common_string] += 1
                    else:
                        keyword_dict["left middle finger"][longest_common_string] = 1
                elif 28 <= mode_number <= 31:
                    if longest_common_string in keyword_dict["left index finger"].keys():
                        keyword_dict["left index finger"][longest_common_string] += 1
                    else:
                        keyword_dict["left index finger"][longest_common_string] = 1
                elif 32 <= mode_number <= 35:
                    if longest_common_string in keyword_dict["right index finger"].keys():
                        keyword_dict["right index finger"][longest_common_string] += 1
                    else:
                        keyword_dict["right index finger"][longest_common_string] = 1
                elif 36 <= mode_number <= 39:
                    if longest_common_string in keyword_dict["right middle finger"].keys():
                        keyword_dict["right middle finger"][longest_common_string] += 1
                    else:
                        keyword_dict["right middle finger"][longest_common_string] = 1
                elif 40 <= mode_number <= 43:
                    if longest_common_string in keyword_dict["right ring finger"].keys():
                        keyword_dict["right ring finger"][longest_common_string] += 1
                    else:
                        keyword_dict["right ring finger"][longest_common_string] = 1
                elif 44 <= mode_number <= 47:
                    if longest_common_string in keyword_dict["right little finger"].keys():
                        keyword_dict["right little finger"][longest_common_string] += 1
                    else:
                        keyword_dict["right little finger"][longest_common_string] = 1
                elif 48 <= mode_number <= 53:
                    if longest_common_string in keyword_dict["little keyboard"].keys():
                        keyword_dict["little keyboard"][longest_common_string] += 1
                    else:
                        keyword_dict["little keyboard"][longest_common_string] = 1
                elif 54 <= mode_number <= 57:
                    if longest_common_string in keyword_dict["26 English characters"].keys():
                        keyword_dict["26 English characters"][longest_common_string] += 1
                    else:
                        keyword_dict["26 English characters"][longest_common_string] = 1
    print(keyword_dict)

    print("Probability analysis...")
    for mode_keyword in keyword_dict.keys():
        mode_keyword_list = []
        for element in keyword_dict[mode_keyword].keys():
            mode_keyword_list.append(element)
        # mode_keyword_list = keyword_dict[mode_keyword].keys()
        for i in range(0, len(mode_keyword_list)):
            for j in range(0, len(mode_keyword_list)):
                if i != j:
                    if mode_keyword_list[i] in mode_keyword_list[j]:
                        keyword_dict[mode_keyword][mode_keyword_list[i]] += keyword_dict[mode_keyword][mode_keyword_list[j]]
    print(keyword_dict)

    f = open(result_filename, "w")
    f.writelines("Number-Keywords-Quantity-Percentage")
    total = len(passwd)
    for mode_keyword in keyword_dict.keys():
        f.writelines("\n" + "# " + mode_keyword + "\n")
        sort_list = sorted(keyword_dict[mode_keyword].items(), key=lambda item: item[1])
        for i in range(1, len(sort_list) + 1):
            print(sort_list[len(sort_list) - i])
            f.writelines(str(i) + " " + str(sort_list[len(sort_list) - i][0]) + " " + str(sort_list[len(sort_list) - i][1])
                         + " " + str(sort_list[len(sort_list) - i][1]/total) + "\n")
        # for keyword in keyword_dict[mode_keyword].keys():
        #     f.writelines(keyword + ": " + str(keyword_dict[mode_keyword][keyword]/total) + "\n")
    f.close()


if __name__ == "__main__":
    csdn_data_path = "www.csdn.net.sql"
    yahoo_data_path = "plaintxt_yahoo.txt"

    csdn_user, csdn_passwd, csdn_mail = read_csdn_data(csdn_data_path)
    yahoo_passwd, yahoo_mail = read_yahoo_data(yahoo_data_path)
    keyboard_hobby_analyse(csdn_passwd, "csdn_keyboard_analyse_result.txt")
    keyboard_hobby_analyse(yahoo_passwd, "yahoo_keyboard_analyse_result.txt")