'''
author:lxj
date:201811
version:1.0
description:analyze date key and create a dic using pcfg
'''
import re
import numpy as np
import time

special_cha = "[\.\s\/\|\_\-]"
#modes in date pwd
Date_key_mode = [
    #y-m-d1:1900-9999,19911001,1991-10-01,1991/10/01,1991.10.01,1991_10_01, 1991101,1991-10-1,1991/10/1,1991.10.1,1991_10_1
    "((((19\d{2})|(20\d{2}))("+special_cha+")?(10|12|0?[13578])("+special_cha+")?(3[01]|[12][0-9]|0?[1-9]))|(((19\d{2})|(20\d{2}))("+special_cha+")?(11|0?[469])("+special_cha+")?(30|[12][0-9]|0?[1-9]))|(((19\d{2})|(20\d{2}))("+special_cha+")?(0?2)("+special_cha+")?(2[0-8]|1[0-9]|0?[1-9]))|(([2][0]00)("+special_cha+")?(0?2)("+special_cha+")?(29))|(([1][9][0][48])("+special_cha+")?(0?2)("+special_cha+")?(29))|(([2][0][0][48])("+special_cha+")?(0?2)("+special_cha+")?(29))|(([1][9][2468][048])("+special_cha+")?(0?2)("+special_cha+")?(29))|(([2][0][2468][048])("+special_cha+")?(0?2)("+special_cha+")?(29))|(([1][9][13579][26])("+special_cha+")?(0?2)("+special_cha+")?(29))|(([2][0][13579][26])("+special_cha+")?(0?2)("+special_cha+")?(29)))",
    
    #y-m-d2:(19)00-99,911001
    #"((\d{2})("+special_cha+")?(10|12|0?[13578])("+special_cha+")?(3[01]|[12]\d|0?[1-9]))|((\d{2})("+special_cha+")?(11|0?[469])("+special_cha+")?(30|[12]\d|0?[1-9]))|((\d{2})("+special_cha+")?(0?2)("+special_cha+")?(2[0-8]|1\d|0?[1-9]))",
    "(((\d{2})("+special_cha+")?(10|12|0?[13578])("+special_cha+")?(3[01]|[12][0-9]|0?[1-9]))|((\d{2})("+special_cha+")?(11|0?[469])("+special_cha+")?(30|[12][0-9]|0?[1-9]))|((\d{2})("+special_cha+")?(0?2)("+special_cha+")?(2[0-8]|1[0-9]|0?[1-9])))",

    #y-m1
    "(((19\d{2})("+special_cha+")?(1[012]|0?[1-9]))|((20\d{2})("+special_cha+")?(1[012]|0?[1-9])))",

    #y-m2
    "(((\d{2})("+special_cha+")?(1[0-2]|0[1-9]))|((\d{2})("+special_cha+")?(1[0-2]|0[1-9])))",

    #m-d
    "(((1[02]|0[13578])("+special_cha+")?(3[01]|[12]\d|0\d))|((11|0[469])("+special_cha+")?(30|[12][0-9]|0\d))|((02)("+special_cha+")?(2[0-8]|1[0-9]|0[1-9])))",

    #no limit date
    "(\d{4}("+special_cha+")?\d{1,2}("+special_cha+")?\d{1,2})",
]#6

def is_num(s):
    '''
    判断字符中是否为整数
    :param s:字符串数字
    :return:
    '''
    try:
        int(s)
        return True
    except ValueError:
        pass
    return False

def load_csdn_key(filename):
    user = []#username # pwd # email
    pwd = []
    mail = []
    print("loading csdn key_file...")
    f = open(filename,'r',encoding="ISO-8859-1")
    for info in f:
        user.append(info.split(" # ")[0])
        pwd.append(info.split(" # ")[1])
        mail.append(info.split(" # ")[2][:-1])#需要去除换行符
    f.close()

    return user,pwd,mail

def load_yahoo_key(filename):
    username = []
    clear_pwd = []

    print("loading yahoo key_file...")
    flag = -1
    f = open(filename,'r',encoding="ISO-8859-1")
    for info in f:
        if info == "user_id   :  user_name  : clear_passwd : passwd\n":
            flag += 1
            continue
        if flag == 0:
            flag += 1
            continue
        if(flag == 1):
            if info == '\n':
                flag = -1
                break
            try:
                username.append(info.split(':')[1])
                clear_pwd.append(info.split(':')[2][:-1])
            except Exception as e:
                pass

    f.close()

    return username,clear_pwd

def ADK(mode,pwd):
    '''
    Analyze Date key
    :return:
    '''
    if re.search(mode,pwd):
        return 1
    else:
        return 0

def Date_Password_Statistics(pwd,date_pwd_dataset_file,dataset_type):
    print(dataset_type+":Date Pwd Analysing...")
    '''
    获取符合日期模式的口令
    '''
    count_datekey = 0

    f = open(date_pwd_dataset_file,'w',encoding="ISO-8859-1")
    f.write("key # mode\n")

    #get the count of date_pwd
    for pwd_element in range(len(pwd)):
        for mode in range(len(Date_key_mode)):
            #print("Mode %d is analyzing..." % (mode + 1))
            if ADK(Date_key_mode[mode],pwd[pwd_element]) == 1:
                f.write(pwd[pwd_element]+" # "+str(mode+1)+"\n")
                count_datekey += 1
                break
    f.close()
    print(dataset_type+":Analyze over.Date pwd num:"+str(count_datekey))

    return count_datekey

def Date_pwd_struct_statistics(pwd,dk_dataset,struct_file,data_part_file,dataset_type):
    '''
    :param pwd:所有口令数量
    :param dk_dataset:
    :param struct_file:存储结构概率
    :data_part_file:存储结构各组成部分中实体内容的概率，如L4中wang占据的概率
    :param flag:
    :save LDSR as struct
    '''
    print(dataset_type+":Struct Analyzing...")

    statistic_struct_type = {}#存储口令结构

    struct_L_dict = {}#结构中每个字母组成成分的统计，如L1数量，L2数量
    struct_D_dict = {}
    struct_S_dict = {}
    struct_R_dict = {}#R3不是表示R结构中内容长度为3，而是表示R结构是第三种日期格式结构

    #因为列表可以记录重复值，可以保留原始情况
    #L_array = []#记录结构中每个字母组成的具体内容，如L2的内容为we，则记录"we"
    #D_array = []
    #S_array = []
    #R_array = []
    #使用字典直接存储对应内容的数量，减少再对列表进行计数的工作
    L_dict = {}
    D_dict = {}
    S_dict = {}
    R_dict = {}

    R_data_struct_relationship = {}#对日期结构的实体内容和结构进关联，之后进行求解频数概率时需要

    f = open(dk_dataset,'r',encoding="ISO-8859-1")
    for info in f:
        if statistic_struct_type == {}:
            statistic_struct_type["L0D0S0R0"]=0
            continue
        s1 = info.split(" # ")[0]#口令
        s2 = info.split(" # ")[1][:-1]#日期密码模式
        struct_type = ""
        R_index = re.search(Date_key_mode[int(s2)-1],s1).span()#日期密码模式需要减1
        R_start,R_end = R_index[0],R_index[1]#日期结构在此口令中的起始和结束位置
        LDS_s1 = s1[:R_start]
        LDS_s2 = s1[R_end:]
        L_count = 0  # 字母
        D_count = 0  # 数字
        S_count = 0  # 特殊字符

        if R_start == 0:
            struct_type += "R"+s2
            if ("R"+s2) in struct_R_dict:
                struct_R_dict["R"+s2] += 1
            else:
                struct_R_dict["R"+s2] = 1
            if s1[R_start:R_end] in R_dict:
                R_dict[s1[R_start:R_end]] += 1
            else:
                R_dict[s1[R_start:R_end]] = 1
            R_data_struct_relationship[s1[R_start:R_end]] = "R"+s2
            flag = -1#-1表示初始状态，0为字母，1为数字，2为特殊字符
            string_index = 0  # 追踪当前结构串的起始位置，如L3D2中D2的起始字符位置
            for element in LDS_s2:
                if is_num(element):
                    if flag == -1 or flag == 1:
                        D_count += 1
                    else:
                        D_count = 1
                        if flag == 0:
                            struct_type += "L"+str(L_count)
                            if ("L" + str(L_count)) in struct_L_dict:
                                struct_L_dict["L" + str(L_count)] += 1
                            else:
                                struct_L_dict["L" + str(L_count)] = 1
                            if LDS_s2[string_index:(string_index + L_count)] in L_dict:
                                L_dict[LDS_s2[string_index:(string_index+L_count)]] += 1
                            else:
                                L_dict[LDS_s2[string_index:(string_index+L_count)]] = 1
                            string_index += L_count
                        else:
                            struct_type += "S"+str(S_count)
                            if ("S" + str(S_count)) in struct_S_dict:
                                struct_S_dict["S" + str(S_count)] += 1
                            else:
                                struct_S_dict["S" + str(S_count)] = 1
                            if LDS_s2[string_index:(string_index+S_count)] in S_dict:
                                S_dict[LDS_s2[string_index:(string_index+S_count)]] += 1
                            else:
                                S_dict[LDS_s2[string_index:(string_index + S_count)]] = 1
                            string_index += S_count
                    flag = 1
                    if element == LDS_s2[-1]:
                        struct_type += "D"+str(D_count)
                        if ("D"+str(D_count)) in struct_D_dict:
                            struct_D_dict["D"+str(D_count)] += 1
                        else:
                            struct_D_dict["D" + str(D_count)] = 1
                        if LDS_s2[string_index:(string_index + D_count)] in D_dict:
                            D_dict[LDS_s2[string_index:(string_index+D_count)]] += 1
                        else:
                            D_dict[LDS_s2[string_index:(string_index+D_count)]] = 1
                elif element in ('abcdefghijklmnopqrstuvwxyz' or 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
                    if flag == -1 or flag == 0:
                        L_count += 1
                    else:
                        L_count = 1
                        if flag == 1:
                            struct_type += "D"+str(D_count)
                            if ("D" + str(D_count)) in struct_D_dict:
                                struct_D_dict["D" + str(D_count)] += 1
                            else:
                                struct_D_dict["D" + str(D_count)] = 1
                            if LDS_s2[string_index:(string_index+D_count)] in D_dict:
                                D_dict[LDS_s2[string_index:(string_index+D_count)]] += 1
                            else:
                                D_dict[LDS_s2[string_index:(string_index+D_count)]] = 1
                            string_index += D_count
                        else:
                            struct_type += "S"+str(S_count)
                            if ("S" + str(S_count)) in struct_S_dict:
                                struct_S_dict["S" + str(S_count)] += 1
                            else:
                                struct_S_dict["S" + str(S_count)] = 1
                            if LDS_s2[string_index:(string_index+S_count)] in S_dict:
                                S_dict[LDS_s2[string_index:(string_index+S_count)]] += 1
                            else:
                                S_dict[LDS_s2[string_index:(string_index+S_count)]] = 1
                            string_index += S_count
                    flag = 0
                    if element == LDS_s2[-1]:
                        struct_type += "L"+str(L_count)
                        if ("L"+str(L_count)) in struct_L_dict:
                            struct_L_dict["L"+str(L_count)] += 1
                        else:
                            struct_L_dict["L" + str(L_count)] = 1
                        if LDS_s2[string_index:(string_index + L_count)] in L_dict:
                            L_dict[LDS_s2[string_index:(string_index+L_count)]] += 1
                        else:
                            L_dict[LDS_s2[string_index:(string_index+L_count)]] = 1
                else:
                    if flag == -1 or flag == 2:
                        S_count += 1
                    else:
                        S_count = 1
                        if flag == 0:
                            struct_type += "L"+str(L_count)
                            if ("L" + str(L_count)) in struct_L_dict:
                                struct_L_dict["L" + str(L_count)] += 1
                            else:
                                struct_L_dict["L" + str(L_count)] = 1
                            if LDS_s2[string_index:(string_index + L_count)] in L_dict:
                                L_dict[LDS_s2[string_index:(string_index+L_count)]] += 1
                            else:
                                L_dict[LDS_s2[string_index:(string_index+L_count)]] = 1
                            string_index += L_count
                        else:
                            struct_type += "D"+str(D_count)
                            if ("D" + str(D_count)) in struct_D_dict:
                                struct_D_dict["D" + str(D_count)] += 1
                            else:
                                struct_D_dict["D" + str(D_count)] = 1
                            if LDS_s2[string_index:(string_index+D_count)] in D_dict:
                                D_dict[LDS_s2[string_index:(string_index+D_count)]] += 1
                            else:
                                D_dict[LDS_s2[string_index:(string_index+D_count)]] = 1
                            string_index += D_count
                    flag = 2
                    if element == LDS_s2[-1]:
                        struct_type += "S"+str(S_count)
                        if ("S"+str(S_count)) in struct_S_dict:
                            struct_S_dict["S"+str(S_count)] += 1
                        else:
                            struct_S_dict["S" + str(S_count)] = 1
                        if LDS_s2[string_index:(string_index + S_count)] in S_dict:
                            S_dict[LDS_s2[string_index:(string_index+S_count)]] += 1
                        else:
                            S_dict[LDS_s2[string_index:(string_index+S_count)]] = 1
            if struct_type in statistic_struct_type:
                statistic_struct_type[struct_type] += 1#更新键值对
            else:
                statistic_struct_type[struct_type] = 1#新建键值对

        else:
            #日期格式非起始结构
            struct_type = ""#归零
            flag = -1
            string_index_1 = 0
            for element in LDS_s1:
                if is_num(element):
                    if flag == -1 or flag == 1:
                        D_count += 1
                    else:
                        D_count = 1
                        if flag == 0:
                            struct_type += "L"+str(L_count)
                            if ("L" + str(L_count)) in struct_L_dict:
                                struct_L_dict["L" + str(L_count)] += 1
                            else:
                                struct_L_dict["L" + str(L_count)] = 1
                            if LDS_s1[string_index_1:(string_index_1 + L_count)] in L_dict:
                                L_dict[LDS_s1[string_index_1:(string_index_1+L_count)]] += 1
                            else:
                                L_dict[LDS_s1[string_index_1:(string_index_1+L_count)]] = 1
                            string_index_1 += L_count
                        else:
                            struct_type += "S"+str(S_count)
                            if ("S" + str(S_count)) in struct_S_dict:
                                struct_S_dict["S" + str(S_count)] += 1
                            else:
                                struct_S_dict["S" + str(S_count)] = 1
                            if LDS_s1[string_index_1:(string_index_1 + S_count)] in S_dict:
                                S_dict[LDS_s1[string_index_1:(string_index_1+S_count)]] += 1
                            else:
                                S_dict[LDS_s1[string_index_1:(string_index_1+S_count)]] = 1
                            string_index_1 += S_count
                    flag = 1
                    if element == LDS_s1[-1]:#末位字符做结束判断并写入结构
                        struct_type += "D"+str(D_count)
                        if ("D" + str(D_count)) in struct_D_dict:
                            struct_D_dict["D" + str(D_count)] += 1
                        else:
                            struct_D_dict["D" + str(D_count)] = 1
                        if LDS_s1[string_index_1:(string_index_1 + D_count)] in D_dict:
                            D_dict[LDS_s1[string_index_1:(string_index_1 + D_count)]] += 1
                        else:
                            D_dict[LDS_s1[string_index_1:(string_index_1 + D_count)]] = 1
                elif element in ('abcdefghijklmnopqrstuvwxyz' or 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
                    if flag == -1 or flag == 0:
                        L_count += 1
                    else:
                        L_count = 1
                        if flag == 1:
                            struct_type += "D"+str(D_count)
                            if ("D" + str(D_count)) in struct_D_dict:
                                struct_D_dict["D" + str(D_count)] += 1
                            else:
                                struct_D_dict["D" + str(D_count)] = 1
                            if LDS_s1[string_index_1:(string_index_1 + D_count)] in D_dict:
                                D_dict[LDS_s1[string_index_1:(string_index_1 + D_count)]] += 1
                            else:
                                D_dict[LDS_s1[string_index_1:(string_index_1 + D_count)]] = 1
                            string_index_1 += D_count
                        else:
                            struct_type += "S"+str(S_count)
                            if ("S" + str(S_count)) in struct_S_dict:
                                struct_S_dict["S" + str(S_count)] += 1
                            else:
                                struct_S_dict["S" + str(S_count)] = 1
                            if LDS_s1[string_index_1:(string_index_1 + S_count)] in S_dict:
                                S_dict[LDS_s1[string_index_1:(string_index_1+S_count)]] += 1
                            else:
                                S_dict[LDS_s1[string_index_1:(string_index_1+S_count)]] = 1
                            string_index_1 += S_count
                    flag = 0
                    if element == LDS_s1[-1]:
                        struct_type += "L"+str(L_count)
                        if ("L" + str(L_count)) in struct_L_dict:
                            struct_L_dict["L" + str(L_count)] += 1
                        else:
                            struct_L_dict["L" + str(L_count)] = 1
                        if LDS_s1[string_index_1:(string_index_1 + L_count)] in L_dict:
                            L_dict[LDS_s1[string_index_1:(string_index_1 + L_count)]] += 1
                        else:
                            L_dict[LDS_s1[string_index_1:(string_index_1 + L_count)]] = 1
                else:
                    if flag == -1 or flag == 2:
                        S_count += 1
                    else:
                        S_count = 1
                        if flag == 0:
                            struct_type += "L"+str(L_count)
                            if ("L" + str(L_count)) in struct_L_dict:
                                struct_L_dict["L" + str(L_count)] += 1
                            else:
                                struct_L_dict["L" + str(L_count)] = 1
                            if LDS_s1[string_index_1:(string_index_1 + L_count)] in L_dict:
                                L_dict[LDS_s1[string_index_1:(string_index_1 + L_count)]] += 1
                            else:
                                L_dict[LDS_s1[string_index_1:(string_index_1 + L_count)]] = 1
                            string_index_1 += L_count
                        else:
                            struct_type += "D"+str(D_count)
                            if ("D" + str(D_count)) in struct_D_dict:
                                struct_D_dict["D" + str(D_count)] += 1
                            else:
                                struct_D_dict["D" + str(D_count)] = 1
                            if LDS_s1[string_index_1:(string_index_1 + D_count)] in D_dict:
                                D_dict[LDS_s1[string_index_1:(string_index_1 + D_count)]] += 1
                            else:
                                D_dict[LDS_s1[string_index_1:(string_index_1 + D_count)]] = 1
                            string_index_1 += D_count
                    flag = 2
                    if element == LDS_s1[-1]:
                        struct_type += "S"+str(S_count)
                        if ("S" + str(S_count)) in struct_S_dict:
                            struct_S_dict["S" + str(S_count)] += 1
                        else:
                            struct_S_dict["S" + str(S_count)] = 1
                        if LDS_s1[string_index_1:(string_index_1 + S_count)] in S_dict:
                            S_dict[LDS_s1[string_index_1:(string_index_1 + S_count)]] += 1
                        else:
                            S_dict[LDS_s1[string_index_1:(string_index_1 + S_count)]] = 1

            struct_type += "R"+s2
            if ("R"+s2) in struct_R_dict:
                struct_R_dict["R"+s2] += 1
            else:
                struct_R_dict["R"+s2] = 1
            if s1[R_start:R_end] in R_dict:
                R_dict[s1[R_start:R_end]] += 1
            else:
                R_dict[s1[R_start:R_end]] = 1
            R_data_struct_relationship[s1[R_start:R_end]] = "R"+s2

            flag = -1
            L_count = 0  # 字母
            D_count = 0  # 数字
            S_count = 0  # 特殊字符
            string_index_2 = 0

            for element in LDS_s2:
                if is_num(element):
                    if flag == -1 or flag == 1:
                        D_count += 1
                    else:
                        D_count = 1
                        if flag == 0:
                            struct_type += "L"+str(L_count)
                            if ("L" + str(L_count)) in struct_L_dict:
                                struct_L_dict["L" + str(L_count)] += 1
                            else:
                                struct_L_dict["L" + str(L_count)] = 1
                            if LDS_s2[string_index_2:(string_index_2 + L_count)] in L_dict:
                                L_dict[LDS_s2[string_index_2:(string_index_2 + L_count)]] += 1
                            else:
                                L_dict[LDS_s2[string_index_2:(string_index_2 + L_count)]] = 1
                            string_index_2 += L_count
                        else:
                            struct_type += "S"+str(S_count)
                            if ("S" + str(S_count)) in struct_S_dict:
                                struct_S_dict["S" + str(S_count)] += 1
                            else:
                                struct_S_dict["S" + str(S_count)] = 1
                            if LDS_s2[string_index_2:(string_index_2 + S_count)] in S_dict:
                                S_dict[LDS_s2[string_index_2:(string_index_2 + S_count)]] += 1
                            else:
                                S_dict[LDS_s2[string_index_2:(string_index_2 + S_count)]] = 1
                            string_index_2 += S_count
                    flag = 1
                    if element == LDS_s2[-1]:
                        struct_type += "D"+str(D_count)
                        if ("D" + str(D_count)) in struct_D_dict:
                            struct_D_dict["D" + str(D_count)] += 1
                        else:
                            struct_D_dict["D" + str(D_count)] = 1
                        if LDS_s2[string_index_2:(string_index_2 + D_count)] in D_dict:
                            D_dict[LDS_s2[string_index_2:(string_index_2 + D_count)]] += 1
                        else:
                            D_dict[LDS_s2[string_index_2:(string_index_2 + D_count)]] = 1
                elif element in ('abcdefghijklmnopqrstuvwxyz' or 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
                    if flag == -1 or flag == 0:
                        L_count += 1
                    else:
                        L_count = 1
                        if flag == 1:
                            struct_type += "D"+str(D_count)
                            if ("D" + str(D_count)) in struct_D_dict:
                                struct_D_dict["D" + str(D_count)] += 1
                            else:
                                struct_D_dict["D" + str(D_count)] = 1
                            if LDS_s2[string_index_2:(string_index_2 + D_count)] in D_dict:
                                D_dict[LDS_s2[string_index_2:(string_index_2 + D_count)]] += 1
                            else:
                                D_dict[LDS_s2[string_index_2:(string_index_2 + D_count)]] = 1
                            string_index_2 += D_count
                        else:
                            struct_type += "S"+str(S_count)
                            if ("S" + str(S_count)) in struct_S_dict:
                                struct_S_dict["S" + str(S_count)] += 1
                            else:
                                struct_S_dict["S" + str(S_count)] = 1
                            if LDS_s2[string_index_2:(string_index_2 + S_count)] in S_dict:
                                S_dict[LDS_s2[string_index_2:(string_index_2 + S_count)]] += 1
                            else:
                                S_dict[LDS_s2[string_index_2:(string_index_2 + S_count)]] = 1
                            string_index_2 += S_count
                    flag = 0
                    if element == LDS_s2[-1]:
                        struct_type += "L"+str(L_count)
                        if ("L" + str(L_count)) in struct_L_dict:
                            struct_L_dict["L" + str(L_count)] += 1
                        else:
                            struct_L_dict["L" + str(L_count)] = 1
                        if LDS_s2[string_index_2:(string_index_2 + L_count)] in L_dict:
                            L_dict[LDS_s2[string_index_2:(string_index_2 + L_count)]] += 1
                        else:
                            L_dict[LDS_s2[string_index_2:(string_index_2 + L_count)]] = 1
                else:
                    if flag == -1 or flag == 2:
                        S_count += 1
                    else:
                        S_count = 1
                        if flag == 0:
                            struct_type += "L"+str(L_count)
                            if ("L" + str(L_count)) in struct_L_dict:
                                struct_L_dict["L" + str(L_count)] += 1
                            else:
                                struct_L_dict["L" + str(L_count)] = 1
                            if LDS_s2[string_index_2:(string_index_2 + L_count)] in L_dict:
                                L_dict[LDS_s2[string_index_2:(string_index_2 + L_count)]] += 1
                            else:
                                L_dict[LDS_s2[string_index_2:(string_index_2 + L_count)]] = 1
                            string_index_2 += L_count
                        else:
                            struct_type += "D"+str(D_count)
                            if ("D" + str(D_count)) in struct_D_dict:
                                struct_D_dict["D" + str(D_count)] += 1
                            else:
                                struct_D_dict["D" + str(D_count)] = 1
                            if LDS_s2[string_index_2:(string_index_2 + D_count)] in D_dict:
                                D_dict[LDS_s2[string_index_2:(string_index_2 + D_count)]] += 1
                            else:
                                D_dict[LDS_s2[string_index_2:(string_index_2 + D_count)]] = 1
                            string_index_2 += D_count
                    flag = 2
                    if element == LDS_s2[-1]:
                        struct_type += "S"+str(S_count)
                        if ("S" + str(S_count)) in struct_S_dict:
                            struct_S_dict["S" + str(S_count)] += 1
                        else:
                            struct_S_dict["S" + str(S_count)] = 1
                        if LDS_s2[string_index_2:(string_index_2 + S_count)] in S_dict:
                            S_dict[LDS_s2[string_index_2:(string_index_2 + S_count)]] += 1
                        else:
                            S_dict[LDS_s2[string_index_2:(string_index_2 + S_count)]] = 1
            if struct_type in statistic_struct_type:
                statistic_struct_type[struct_type] += 1#更新键值对
            else:
                statistic_struct_type[struct_type] = 1#新建键值对

    f.close()

    del statistic_struct_type["L0D0S0R0"]
    '''
    记录每种结构口令概率
    '''
    print("Analyzing percentage of struct...")
    #test_num = 0
    f = open(struct_file,'w',encoding="ISO-8859-1")
    f.write("struct # percentage\n")
    for s_type in statistic_struct_type:
        f.write(s_type+" # "+str(statistic_struct_type[s_type]/pwd)+"\n")
        #test_num += statistic_struct_type[s_type]
    f.close()
    print(dataset_type + ":Analyze over.Struct types num:", len(statistic_struct_type))

    '''
    统计每种结构组成中的具体构成内容的概率
    '''
    print("Analyzing percentage of data in struct....")
    f = open(data_part_file,'w',encoding="ISO-8859-1")
    f.write("data # struct_part # percentage\n")
    for key in L_dict:
        f.write(key+" # L"+str(len(key))+" # "+str(L_dict[key]/struct_L_dict["L"+str(len(key))])+"\n")
    for key in D_dict:
        f.write(key+" # D"+str(len(key))+" # "+str(D_dict[key]/struct_D_dict["D"+str(len(key))])+"\n")
    for key in S_dict:
        f.write(key + " # S" + str(len(key)) + " # " + str(S_dict[key] / struct_S_dict["S" + str(len(key))]) + "\n")
    for key in R_dict:
        f.write(key + " # " + R_data_struct_relationship[key] + " # " + str(R_dict[key] / struct_R_dict[R_data_struct_relationship[key]]) + "\n")
    f.close()
    print(dataset_type+"Analyze over.")

    return 0

def random_select(struct_list, probability_list):
    # 生成概率选择空间
    space_list = []
    space_begin = 0
    for probability in probability_list:
        space_list.append(space_begin)
        space_begin += probability

    # 随机选取概率
    random_point = space_begin * np.random.random()

    selected_str = ""
    for i in range(0, len(space_list)):
        if space_begin > random_point >= space_list[len(space_list) - 1]:
            selected_str = struct_list[len(space_list) - 1]
            break
        elif space_list[i + 1] > random_point >= space_list[i]:
            selected_str = struct_list[i]
            break
    return selected_str

def Generate_dict(struct_file,element_file):
    '''
    根据PCFG算法，依据结构概率生成日期字典
    :param struct_file:
    :return:
    '''
    struct_list = []
    struct_probability_list = []
    f = open(struct_file,"r",encoding="ISO-8859-1")
    for info in f:
        if struct_list == []:
            struct_list.append(0)
            continue
        if struct_list[0] == 0:
            del struct_list[0]
        struct_list.append(info.split(" # ")[0])
        struct_probability_list.append(float(info.split(" # ")[-1][:-1]))
    f.close()

    selected_struct = random_select(struct_list,struct_probability_list)

    generated_pwd = ""
    #获取结构内容进行选取
    #每个子结构如L2先进行判别，再将内容及概率进行传递选取
    element_struct = []
    element_data = []
    element_probability = []

    f = open(element_file,'r',encoding="ISO-8859-1")
    for info in f:
        if element_struct == []:
            element_struct.append(0)
            continue
        if element_struct[0] == 0:
            del element_struct[0]
        element_struct.append(info.split(" # ")[1])
        element_data.append(info.split(" # ")[0])
        element_probability.append(float(info.split(" # ")[-1][:-1]))
    f.close()

    #识别选择的结构的组成
    patern = "[LDSR]\d{1,2}"
    c_patern = re.compile(patern)
    struct_part = c_patern.findall(selected_struct)#每个子结构
    for struct_type in struct_part:
        #需要把同种结构内容取出
        select_data_list = []
        select_probability_list = []
        for i in range(len(element_struct)):
            if element_struct[i] == struct_type:
                select_data_list.append(element_data[i])
                select_probability_list.append(element_probability[i])
        #index = element_struct.index(struct_type)
        #temp1 = element_data[index]
        #temp2 = element_probability[index]
        generated_pwd += random_select(select_data_list,select_probability_list)

    return generated_pwd

if __name__ == '__main__':
    print("Begin Analyze key_file!")
    start_time = time.time()

    #载入原始密码库
    csdn_file = "www.csdn.net.sql"
    #csdn_name,csdn_pwd,csdn_mail = load_csdn_key(csdn_file)
    yahoo_file = "plaintxt_yahoo.txt"
    #yahoo_name,yahoo_pwd = load_yahoo_key(yahoo_file)

    #记录符合日期密码模式的密码
    print("Date key mode:")
    for mode in range(len(Date_key_mode)):
        print("%d %s" % (mode + 1, Date_key_mode[mode]))

    csdn_date_pwd_dataset_file = "csdn_date_pwd_dataset.txt"
    yahoo_date_pwd_dataset_file = "yahoo_date_pwd_dataset.txt"

    #csdn_datekey_number = Date_Password_Statistics(csdn_pwd,csdn_date_pwd_dataset_file,"csdn")
    #yahoo_datekey_number = Date_Password_Statistics(yahoo_pwd,yahoo_date_pwd_dataset_file,"yahoo")
    #print("csdn date_key dataset:%s",csdn_datekey_number/len(csdn_pwd))
    #print("yahoo data_key dataset:%s",yahoo_datekey_number/len(yahoo_pwd))

    #记录口令结构及概率
    csdn_key_struct_file = "csdn_struct.txt"
    yahoo_key_struct_file = "yahoo_struct.txt"
    # 记录口令结构中具体内容概率
    csdn_data_element_file = "csdn_element.txt"
    yahoo_data_element_file = "yahoo_element.txt"
    #Date_pwd_struct_statistics(csdn_datekey_number,csdn_date_pwd_dataset_file,csdn_key_struct_file,csdn_data_element_file,"csdn")
    #Date_pwd_struct_statistics(yahoo_datekey_number,yahoo_date_pwd_dataset_file,yahoo_key_struct_file,yahoo_data_element_file,"yahoo")

    #应用PCFG算法生成攻击字典
    generate_pwd_number = 10000

    generation_csdn_passwd_dict_path = "generation_csdn_date_passwd_dict.txt"
    generation_yahoo_passwd_dict_path = "generation_yahoo_date_passwd_dict.txt"

    print("Generating csdn passwd dict...")
    csdn_passwd_dict = open(generation_csdn_passwd_dict_path, "w",encoding="ISO-859-1")
    for i in range(generate_pwd_number):
        print("Round %s generating..." % (i+1))
        generated_passwd = Generate_dict(csdn_key_struct_file,csdn_data_element_file)
        csdn_passwd_dict.write(generated_passwd + "\n")
    csdn_passwd_dict.close()

    print("Generating yahoo passwd dict...")
    yahoo_passwd_dict = open(generation_yahoo_passwd_dict_path, "w",encoding="ISO-8859-1")
    for i in range(generate_pwd_number):
        print("Round %s generating..." % (i+1))
        generated_passwd = Generate_dict(yahoo_key_struct_file,yahoo_data_element_file)
        yahoo_passwd_dict.write(generated_passwd + "\n")
    yahoo_passwd_dict.close()

    end_time = time.time()
    if (end_time - start_time) > 3600:
        print("Cost time:%s hours"%((end_time - start_time)/3600))
    else:
        print("Cost time:%s seconds"%(end_time - start_time))
    print("Date password dictionary finished !")


