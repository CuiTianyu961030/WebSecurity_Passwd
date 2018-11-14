#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Using PCFG algorithm to generate CSDN and Yahoo user passwords.

The analyse result consists of
keyboard password dataset, pattern matched result, keyword result, structure result, and element result.

The generated password dictionaries consist of
CSDN and Yahoo password dictionaries.

For more information see https://github.com/CuiTianyu961030/WebSecurity_Passwd.
"""

import sys
import re
import numpy as np


def swap(a, b):
    temp = a
    a = b
    b = temp
    return a, b


# 读取csdn数据库
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


# 读取yahoo数据库
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


# LCS匹配口令与键盘模式的最长公共子串
def longest_common_substring(pattern, passwd):
    dp = [[0 for j in range(len(pattern) + 1)] for i in range(len(passwd) + 1)]

    maximum_longth = -1
    string_end = -1

    # 动态规划并标记最大长度回淑求取最长子串
    for i in range(1, len(passwd) + 1):
        for j in range(1, len(pattern) + 1):
            if passwd[i-1] == pattern[j-1]:
                dp[i][j] = dp[i-1][j-1] + 1

            if dp[i][j] > maximum_longth:
                maximum_longth = dp[i][j]
                string_end = i

    longest_common_strng = passwd[string_end - maximum_longth:string_end]

    return maximum_longth, longest_common_strng, string_end


# 按键盘模式分析口令的键盘关键字概率分布
def keyboard_hobby_analyse(passwd, result_filename, dataset_filename):

    # 键盘模式下的14种模式分析

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
    # 58-101 Reverse fingering order
    # 102-107 Random keyboard line combination

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
        "ZYXWVUTSRQPONMLKJIHGFEDCBA",

        "`12q3wa",
        "aw3q21`",
        "~!@Q#WA",
        "AW#Q@!~",

        "zse4",
        "4esz",
        "ZSE$",
        "$ESZ",

        "xdr5",
        "5rdx",
        "XDR%",
        "%RDX",

        "cft6",
        "6tfc",
        "CFT^",
        "^TFC",

        "vgy7",
        "7ygv",
        "VGY&",
        "&YGV",

        "bhu8",
        "8uhb",
        "BHU*",
        "*UHB",

        "nji9",
        "9ijn",
        "NJI(",
        "(IJN",

        "mko0",
        "0okm",
        "MKO)",
        ")OKM",

        ",lp-",
        "-pl,",
        "<LP_",
        "_PL<",

        ".;[=",
        "=[;.",
        ">:{+",
        "+{:>",

        "/']\\",
        "\\]'/",
        "?\"}|",
        "|}\"?",

        "1q2w3e4r5t6y7u8i9o0p",
        "1Q2W3E4R5T6Y7U8I9O0P",
        "1a2s3d4f5g6h7j8k9l0;",
        "1A2S3D4F5G6H7J8K9L0;",
        "1z2x3c4v5b6n7m8,9.0/",
        "1Z2X3C4V5B6N7M8,9.0/"
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
        "26 English characters": {},
        "Reverse fingering order": {},
        "Random keyboard line combination": {}
    }

    # 存储含有键盘模式的键盘口令数据集
    print("Genearting keyboard password dataset...")
    f = open(dataset_filename, "w", encoding="ISO-8859-1")

    # 标志当前口令是否已匹配到键盘模式
    passwd_flag = [0 for i in range(len(passwd))]

    for mode_number in range(0, len(pattern)):
        print("Mode %s analysing..." % mode_number)
        password_index = 0
        for passwd_element in passwd:

            # LCS模式匹配寻找关键字
            longest_len, longest_common_string, string_end = longest_common_substring(pattern[mode_number], passwd_element)

            # 保留关键字长度大于3的所有口令及关键字
            if longest_len >= 3:
                if passwd_flag[password_index] == 0:
                    f.writelines(passwd_element + " \\ " + str(string_end-longest_len) + " \\ " + str(string_end) + "\n")
                    passwd_flag[password_index] = 1

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
                elif 58 <= mode_number <= 101:
                    if longest_common_string in keyword_dict["Reverse fingering order"].keys():
                        keyword_dict["Reverse fingering order"][longest_common_string] += 1
                    else:
                        keyword_dict["Reverse fingering order"][longest_common_string] = 1
                elif 102 <= mode_number <= 107:
                    if longest_common_string in keyword_dict["Random keyboard line combination"].keys():
                        keyword_dict["Random keyboard line combination"][longest_common_string] += 1
                    else:
                        keyword_dict["Random keyboard line combination"][longest_common_string] = 1

            password_index += 1

    f.close()
    # print(keyword_dict)

    # print("Probability analysis...")
    # for mode_keyword in keyword_dict.keys():
    #     mode_keyword_list = []
    #     for element in keyword_dict[mode_keyword].keys():
    #         mode_keyword_list.append(element)
    #     # mode_keyword_list = keyword_dict[mode_keyword].keys()
    #     for i in range(0, len(mode_keyword_list)):
    #         for j in range(0, len(mode_keyword_list)):
    #             if i != j:
    #                 if mode_keyword_list[i] in mode_keyword_list[j]:
    #                     keyword_dict[mode_keyword][mode_keyword_list[i]] += keyword_dict[mode_keyword][mode_keyword_list[j]]
    # print(keyword_dict)

    # 生成键盘模式下关键字概率分析结果
    print("Generating pattern matched result...")
    f = open(result_filename, "w")
    f.writelines("Number \ Keywords \ Quantity \ Percentage")
    total = len(passwd)
    for mode_keyword in keyword_dict.keys():

        f.writelines("\n" + "# " + mode_keyword + "\n")
        sort_list = sorted(keyword_dict[mode_keyword].items(), key=lambda item: item[1])

        for i in range(1, len(sort_list) + 1):
            # print(sort_list[len(sort_list) - i])
            f.writelines(str(i) + " \\ " + str(sort_list[len(sort_list) - i][0]) + " \\ " + str(sort_list[len(sort_list) - i][1])
                         + " \\ " + str(sort_list[len(sort_list) - i][1]/total) + "\n")
    f.close()


# 分析含有键盘模式口令的口令结构
def keyboard_structure_analyse(keyboard_keyword_dataset, keyboard_password_dataset, keyboard_structure):

    print("Keyboard structure analysing...")
    keyword_list = []
    keyword_probability_list = []
    len_list = []

    # 读取键盘关键字概率分析结果
    f = open(keyboard_keyword_dataset, "r")
    for line in f:
        # print(re.match(r'\d', line))
        if re.match(r'\d', line) is not None:
            keyword_list.append(line.split(" \\ ")[1])
            keyword_probability_list.append(line.split(" \\ ")[3])
            len_list.append(len(line.split(" \\ ")[1]))
    f.close()

    # 寻找关键字最大长度
    maximum = 0
    for i in range(0, len(len_list)):
        if len_list[i] > maximum:
            maximum = len_list[i]

    # 生成不同关键字长度下的关键字概率文件
    print("Generating keyword result...")
    for i in range(3, maximum + 1):
        f = open(str(i) + "_length_keyword.txt", "w")
        for j in range(0, len(len_list)):
            if len_list[j] == i:
                f.writelines(keyword_list[j] + " \\ " + keyword_probability_list[j])
        f.close()

    # 分析键盘数据集口令结构
    structure_dict = {}
    keyword_position = []
    keyword_position_index = 0

    # 读取键盘口令数据集
    f = open(keyboard_password_dataset, "r")
    for line in f:
        passwd = line.split(" \\ ")[0]

        # 标记已匹配的键盘关键字在口令中的出现位置
        start = int(line.split(" \\ ")[1])
        end = int(line.split(" \\ ")[2])
        keyword_position.append([(start, end)])

        # 重复匹配其他关键字，检测复杂键盘口令结构
        for keyword in keyword_list:
            if len(keyword) <= len(passwd) and keyword in passwd:

                # 从后向前匹配原则，检测口令未匹配部分是否存在关键字
                new_start = passwd.rfind(keyword)
                new_end = new_start + len(keyword)

                # 存储所有关键字起始终止位置
                if new_end <= int(start) or int(end) <= new_start:
                    index_list = []
                    index_list.append((start, end))
                    index_list.append((new_start, new_end))
                    keyword_position[keyword_position_index] = index_list
                    break

                # 更新原匹配关键字长度
                elif new_start <= int(start) and int(end) <= new_end:
                    start = new_start
                    end = new_end

        # 生成口令结构
        if len(keyword_position[keyword_position_index]) == 1:
            k_start, k_end = keyword_position[keyword_position_index][0]

            struct_sequence = ""
            for i in range(0, len(passwd)):
                if k_start <= i < k_end:
                    struct_sequence += 'a'

                elif i < k_start or i >= k_end:
                    if re.match(r'\d', passwd[i]) is not None:
                        struct_sequence += 'd'
                    elif re.match(r'[a-zA-Z]', passwd[i]) is not None:
                        struct_sequence += 'l'
                    else:
                        struct_sequence += 's'

        elif len(keyword_position[keyword_position_index]) == 2:

            k1_start, k1_end = keyword_position[keyword_position_index][0]
            k2_start, k2_end = keyword_position[keyword_position_index][1]
            struct_sequence = ""
            if k2_end <= k1_start:
                k1_start, k2_start = swap(k1_start, k2_start)
                k1_end, k2_end = swap(k1_end, k2_end)

            for i in range(0, len(passwd)):

                if k1_start <= i < k1_end:
                    struct_sequence += 'a'
                elif k2_start <= i < k2_end:
                    struct_sequence += 'b'
                elif i < k1_start or k1_end <= i < k2_start or i >= k2_end:
                    if re.match(r'\d', passwd[i]) is not None:
                        struct_sequence += 'd'
                    elif re.match(r'[a-zA-Z]', passwd[i]) is not None:
                        struct_sequence += 'l'
                    else:
                        struct_sequence += 's'

        count = 0
        structure = ""
        for i in range(0, len(struct_sequence)):
            count += 1
            if i == len(struct_sequence) - 1:
                structure = structure + struct_sequence[i] + str(count)
                break
            if struct_sequence[i] != struct_sequence[i+1]:
                structure = structure + struct_sequence[i] + str(count)
                count = 0

        if structure in structure_dict.keys():
            structure_dict[structure] += 1
        else:
            structure_dict[structure] = 1
        keyword_position_index += 1
    f.close()

    # 存储口令结构概率文件
    print("Generating structure result...")
    f = open(keyboard_structure, "w")
    sort_list = sorted(structure_dict.items(), key=lambda item: item[1])
    for i in range(1, len(sort_list) + 1):
        # print(sort_list[len(sort_list) - i])
        f.writelines(str(i) + " \\ " + str(sort_list[len(sort_list) - i][0]) + " \\ " + str(sort_list[len(sort_list) - i][1])
                     + " \\ " + str(float(sort_list[len(sort_list) - i][1]) / keyword_position_index) + "\n")
    f.close()


# 分析结构下的构成元素概率分布
def structure_element_analyse(keyboard_password_dataset):

    print("Structure element analysing...")
    passwd_list = []
    f = open(keyboard_password_dataset, "r")
    for line in f:
        passwd_list.append(line.split(" \\ ")[0])
    f.close()

    # 分别匹配数组字母字符元素
    digital_dict = {}
    language_dict = {}
    string_dict = {}
    for passwd in passwd_list:
        d_result = re.findall(r'\d+', passwd)
        l_result = re.findall(r'[a-zA-Z]+', passwd)
        s_result = re.findall(r'[^0-9a-zA-Z]+', passwd)
        for element in d_result:
            if element in digital_dict.keys():
                digital_dict[element] += 1
            else:
                digital_dict[element] = 1
        for element in l_result:
            if element in language_dict.keys():
                language_dict[element] += 1
            else:
                language_dict[element] = 1
        for element in s_result:
            if element in string_dict.keys():
                string_dict[element] += 1
            else:
                string_dict[element] = 1

    digital_list = []
    language_list = []
    string_list = []

    digital_probability_list = []
    language_probability_list = []
    string_probability_list = []

    digital_length_list = []
    language_length_list = []
    string_length_list = []

    digital_total = 0
    for digital, count in digital_dict.items():
        digital_list.append(digital)
        digital_probability_list.append(count)
        digital_length_list.append(len(digital))
        digital_total += count
    language_total = 0
    for language, count in language_dict.items():
        language_list.append(language)
        language_probability_list.append(count)
        language_length_list.append(len(language))
        language_total += count
    string_total = 0
    for string, count in string_dict.items():
        string_list.append(string)
        string_probability_list.append(count)
        string_length_list.append(len(string))
        string_total += count

    # 求取构成元素的最大长度
    digital_length_maximum = 0
    for i in range(0, len(digital_length_list)):
        if digital_length_list[i] > digital_length_maximum:
            digital_length_maximum = digital_length_list[i]

    language_length_maximum = 0
    for i in range(0, len(language_length_list)):
        if language_length_list[i] > language_length_maximum:
            language_length_maximum = language_length_list[i]

    string_length_maximum = 0
    for i in range(0, len(string_length_list)):
        if string_length_list[i] > string_length_maximum:
            string_length_maximum = string_length_list[i]

    # 生成不同元素长度下的元素组合概率结果
    print("Generating element result...")
    for i in range(1, digital_length_maximum + 1):
        f = open(str(i) + "_length_digital.txt", "w")
        for j in range(0, len(digital_length_list)):
            if digital_length_list[j] == i:
                f.writelines(digital_list[j] + " \\ " + str(digital_probability_list[j] / digital_total) + "\n")
        f.close()
    for i in range(1, language_length_maximum + 1):
        f = open(str(i) + "_length_language.txt", "w")
        for j in range(0, len(language_length_list)):
            if language_length_list[j] == i:
                f.writelines(language_list[j] + " \\ " + str(language_probability_list[j] / language_total) + "\n")
        f.close()
    for i in range(1, string_length_maximum + 1):
        f = open(str(i) + "_length_string.txt", "w")
        for j in range(0, len(string_length_list)):
            if string_length_list[j] == i:
                f.writelines(string_list[j] + " \\ " + str(string_probability_list[j] / string_total) + "\n")
        f.close()


# 依照概率随机选择生成口令结构和元素组成
def random_select_structure(keyboard_structure_list, keyboard_structure_probability_list):

    # 生成概率选择空间
    structure_space_list = []
    space_begin = 0
    for probability in keyboard_structure_probability_list:
        structure_space_list.append(space_begin)
        space_begin += probability
        # structure_space_list.append(space_begin)

    # 随机选取概率空间中的坐标值
    # seed = np.random.randint(0, 10000)
    # np.random.seed(seed)
    random_point = space_begin * np.random.random()

    selected_structure = ""
    for i in range(0, len(structure_space_list)):
        if space_begin > random_point >= structure_space_list[len(structure_space_list) - 1]:
            selected_structure = keyboard_structure_list[len(structure_space_list) - 1]
            break
        elif structure_space_list[i + 1] > random_point >= structure_space_list[i]:
            selected_structure = keyboard_structure_list[i]
            break
    return selected_structure


# pcfg算法根据概率分布生成键盘口令字典
def keyboard_passwd_generation(keyboard_structure_path):

    # 读取结构概率分布结果
    keyboard_structure_list = []
    keyboard_structure_probability_list = []
    f = open(keyboard_structure_path, "r")
    for line in f:
        keyboard_structure_list.append(line.split(" \\ ")[1])
        keyboard_structure_probability_list.append(float(line.split(" \\ ")[3]))
    f.close()

    # 依照结构概率随机选择口令生成结构
    selected_structure = random_select_structure(keyboard_structure_list, keyboard_structure_probability_list)

    # 读取结构构成内容
    element_flag = []
    element_length = []
    # element_length = 0
    for i in range(0, len(selected_structure)):
        if re.match(r'[a-z]', selected_structure[i]) is not None:
            element_flag.append(selected_structure[i])
            if i + 2 == len(selected_structure) - 1 and re.match(r'\d', selected_structure[i + 2]) is not None:
                element_length.append(int(selected_structure[i + 1:i + 2]))
                break
            if i + 1 == len(selected_structure) - 1:
                element_length.append(int(selected_structure[i + 1]))
                break
            if re.match(r'\d', selected_structure[i + 2]) is not None:
                element_length.append(int(selected_structure[i + 1:i + 2]))
            else:
                element_length.append(int(selected_structure[i + 1]))

    for i in range(0, len(element_flag)):
        if element_flag[i] == "d":
            element_flag[i] = "digital"
        elif element_flag[i] == "l":
            element_flag[i] = "language"
        elif element_flag[i] == "s":
            element_flag[i] = "string"
        elif element_flag[i] == "a" or element_flag[i] == "b":
            element_flag[i] = "keyword"

    # 寻找结构下的口令元素组合
    generated_passwd = ""
    for i in range(0, len(element_flag)):
        element_list = []
        element_probability_list = []
        element_filepath = str(element_length[i]) + "_length_" + element_flag[i] + ".txt"
        f = open(element_filepath, "r")
        for line in f:
            element_list.append(line.split(" \\ ")[0])
            element_probability_list.append(float(line.split(" \\ ")[1]))
        f.close()

        # 依照元素组合概率随机选择口令元素组合
        selected_element = random_select_structure(element_list, element_probability_list)
        generated_passwd += selected_element

    return generated_passwd


if __name__ == "__main__":

    # 口令原始数据库
    csdn_data_path = "www.csdn.net.sql"
    yahoo_data_path = "plaintxt_yahoo.txt"

    # 含有键盘模式的口令数据库
    csdn_keyboard_password_dataset_path = "csdn_keyboard_password_dataset.txt"
    yahoo_keyboard_password_dataset_path = "yahoo_keyboard_password_dataset.txt"

    # 键盘关键字概率分布结果
    csdn_keyboard_keyword_dataset_path = "csdn_keyboard_analyse_result.txt"
    yahoo_keyboard_keyword_dataset_path = "yahoo_keyboard_analyse_result.txt"

    # 键盘结构概率分布结果
    csdn_keyboard_structure_path ="csdn_keyboard_structure.txt"
    yahoo_keyboard_structure_path = "yahoo_keyboard_structure.txt"

    csdn_user, csdn_passwd, csdn_mail = read_csdn_data(csdn_data_path)
    yahoo_passwd, yahoo_mail = read_yahoo_data(yahoo_data_path)

    keyboard_hobby_analyse(csdn_passwd, csdn_keyboard_keyword_dataset_path, csdn_keyboard_password_dataset_path)
    keyboard_hobby_analyse(yahoo_passwd, yahoo_keyboard_keyword_dataset_path, yahoo_keyboard_password_dataset_path)

    keyboard_structure_analyse(csdn_keyboard_keyword_dataset_path, csdn_keyboard_password_dataset_path, csdn_keyboard_structure_path)
    keyboard_structure_analyse(yahoo_keyboard_keyword_dataset_path, yahoo_keyboard_password_dataset_path, yahoo_keyboard_structure_path)


    structure_element_analyse(csdn_keyboard_password_dataset_path)
    #
    # # 生成口令字典容量及口令字典保存路径
    # # generate_passwd_number = 100000
    generate_passwd_number = sys.argv[1]
    print(generate_passwd_number)
    generation_csdn_passwd_dict_path = "generation_csdn_keyboard_passwd_dict.txt"
    generation_yahoo_passwd_dict_path = "generation_yahoo_passwd_keyboard_dict.txt"

    print("Generating csdn passwd dict...")
    csdn_passwd_dict = open(generation_csdn_passwd_dict_path, "w")
    for i in range(0, generate_passwd_number + 1):
        print("Round %s generating..." % i)
        generated_passwd = keyboard_passwd_generation(csdn_keyboard_structure_path)
        csdn_passwd_dict.writelines(generated_passwd + "\n")
    csdn_passwd_dict.close()

    structure_element_analyse(yahoo_keyboard_password_dataset_path)

    print("Generating yahoo passwd dict...")
    yahoo_passwd_dict = open(generation_yahoo_passwd_dict_path, "w")
    for i in range(0, generate_passwd_number + 1):
        print("Round %s generating..." % i)
        generated_passwd = keyboard_passwd_generation(yahoo_keyboard_structure_path)
        yahoo_passwd_dict.writelines(generated_passwd + "\n")
    yahoo_passwd_dict.close()

    print("Password dictionary finished !")
