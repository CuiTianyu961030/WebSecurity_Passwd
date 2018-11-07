'''
author:lxj
date:201811
version:1.0
description:analyze date key and create a dic using pcfg
'''
import re

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
    #username # pwd # email
    user = []
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

def Date_pwd_struct_statistics(pwd,dk_dataset,struct_file,dataset_type):
    '''
    :param pwd:所有口令数量
    :param dk_dataset:
    :param struct_file:
    :param flag:
    :save LDSR as struct
    '''
    print(dataset_type+":Struct Analyzing...")
    statistic_struct_type = {}
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
            flag = -1#-1表示初始状态，0为字母，1为数字，2为特殊字符
            for element in LDS_s2:
                if is_num(element):
                    if flag == -1 or flag == 1:
                        D_count += 1
                    else:
                        D_count = 1
                        if flag == 0:
                            struct_type += "L"+str(L_count)
                        else:
                            struct_type += "S"+str(S_count)
                    flag = 1
                    if element == LDS_s2[-1]:
                        struct_type += "D"+str(D_count)
                elif element in ('abcdefghijklmnopqrstuvwxyz' or 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
                    if flag == -1 or flag == 0:
                        L_count += 1
                    else:
                        L_count = 1
                        if flag == 1:
                            struct_type += "D"+str(D_count)
                        else:
                            struct_type += "S"+str(S_count)
                    flag = 0
                    if element == LDS_s2[-1]:
                        struct_type += "L"+str(L_count)
                else:
                    if flag == -1 or flag == 2:
                        S_count += 1
                    else:
                        S_count = 1
                        if flag == 0:
                            struct_type += "L"+str(L_count)
                        else:
                            struct_type += "D"+str(D_count)
                    flag = 2
                    if element == LDS_s2[-1]:
                        struct_type += "S"+str(S_count)
            if struct_type in statistic_struct_type:
                statistic_struct_type[struct_type] += 1#更新键值对
            else:
                statistic_struct_type[struct_type] = 1#新建键值对

        else:
            #日期格式非起始结构
            struct_type = ""#归零
            flag = -1
            for element in LDS_s1:
                if is_num(element):
                    if flag == -1 or flag == 1:
                        D_count += 1
                    else:
                        D_count = 1
                        if flag == 0:
                            struct_type += "L"+str(L_count)
                        else:
                            struct_type += "S"+str(S_count)
                    flag = 1
                    if element == LDS_s1[-1]:#末位字符做结束判断并写入结构
                        struct_type += "D"+str(D_count)
                elif element in ('abcdefghijklmnopqrstuvwxyz' or 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
                    if flag == -1 or flag == 0:
                        L_count += 1
                    else:
                        L_count = 1
                        if flag == 1:
                            struct_type += "D"+str(D_count)
                        else:
                            struct_type += "S"+str(S_count)
                    flag = 0
                    if element == LDS_s1[-1]:
                        struct_type += "L"+str(L_count)
                else:
                    if flag == -1 or flag == 2:
                        S_count += 1
                    else:
                        S_count = 1
                        if flag == 0:
                            struct_type += "L"+str(L_count)
                        else:
                            struct_type += "D"+str(D_count)
                    flag = 2
                    if element == LDS_s1[-1]:
                        struct_type += "S"+str(S_count)

            struct_type += "R"+s2

            flag = -1
            L_count = 0  # 字母
            D_count = 0  # 数字
            S_count = 0  # 特殊字符

            for element in LDS_s2:
                if is_num(element):
                    if flag == -1 or flag == 1:
                        D_count += 1
                    else:
                        D_count = 1
                        if flag == 0:
                            struct_type += "L"+str(L_count)
                        else:
                            struct_type += "S"+str(S_count)
                    flag = 1
                    if element == LDS_s2[-1]:
                        struct_type += "D"+str(D_count)
                elif element in ('abcdefghijklmnopqrstuvwxyz' or 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
                    if flag == -1 or flag == 0:
                        L_count += 1
                    else:
                        L_count = 1
                        if flag == 1:
                            struct_type += "D"+str(D_count)
                        else:
                            struct_type += "S"+str(S_count)
                    flag = 0
                    if element == LDS_s2[-1]:
                        struct_type += "L"+str(L_count)
                else:
                    if flag == -1 or flag == 2:
                        S_count += 1
                    else:
                        S_count = 1
                        if flag == 0:
                            struct_type += "L"+str(L_count)
                        else:
                            struct_type += "D"+str(D_count)
                    flag = 2
                    if element == LDS_s2[-1]:
                        struct_type += "S"+str(S_count)
            if struct_type in statistic_struct_type:
                statistic_struct_type[struct_type] += 1#更新键值对
            else:
                statistic_struct_type[struct_type] = 1#新建键值对

    f.close()

    del statistic_struct_type["L0D0S0R0"]
    '''
    记录每种结构口令概率
    '''
    #test_num = 0
    f = open(struct_file,'w',encoding="ISO-8859-1")
    f.write("struct # percentage\n")
    for s_type in statistic_struct_type:
        f.write(s_type+" # "+str(statistic_struct_type[s_type]/pwd)+"\n")
        #test_num += statistic_struct_type[s_type]
    f.close()

    print(dataset_type+":Analyze over.Struct types num:",len(statistic_struct_type))
    return 0

if __name__ == '__main__':
    print("Begin Analyze key_file!")

    #载入原始密码库
    csdn_file = "www.csdn.net.sql"
    csdn_name,csdn_pwd,csdn_mail = load_csdn_key(csdn_file)
    yahoo_file = "plaintxt_yahoo.txt"
    yahoo_name,yahoo_pwd = load_yahoo_key(yahoo_file)

    #记录符合日期密码模式的密码
    print("Date key mode:")
    for mode in range(len(Date_key_mode)):
        print("%d %s" % (mode + 1, Date_key_mode[mode]))

    csdn_date_pwd_dataset_file = "csdn_date_pwd_dataset.txt"
    yahoo_date_pwd_dataset_file = "yahoo_date_pwd_dataset.txt"

    csdn_datekey_number = Date_Password_Statistics(csdn_pwd,csdn_date_pwd_dataset_file,"csdn")
    yahoo_datekey_number = Date_Password_Statistics(yahoo_pwd,yahoo_date_pwd_dataset_file,"yahoo")
    print("csdn date_key dataset:%s",csdn_datekey_number/len(csdn_pwd))
    print("yahoo data_key dataset:%s",yahoo_datekey_number/len(yahoo_pwd))

    #记录口令结构及概率
    csdn_key_struct_file = "csdn_struct.txt"
    yahoo_key_struct_file = "yahoo_stauct.txt"
    Date_pwd_struct_statistics(len(csdn_pwd),csdn_date_pwd_dataset_file,csdn_key_struct_file,"csdn")
    Date_pwd_struct_statistics(len(yahoo_pwd),yahoo_date_pwd_dataset_file,yahoo_key_struct_file,"yahoo")

