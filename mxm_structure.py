# -*- coding: utf-8 -*-
"""
Created on Sun Oct 28 10:53:13 2018

@author: mxm
"""
#将对应类型的字符串加入相应字典
def add_dict(NewSign,ch_str,alpha_dict,digit_dict,char_dict):
    if NewSign == 'L':
        if ch_str in alpha_dict:
            alpha_dict[ch_str] += 1
        else :
            alpha_dict[ch_str] = 1
    elif NewSign == 'D':
        if ch_str in digit_dict:
            digit_dict[ch_str] += 1
        else :
            digit_dict[ch_str] = 1
    else:
        if ch_str in char_dict:
            char_dict[ch_str] += 1
        else :
            char_dict[ch_str] = 1
    return (alpha_dict,digit_dict,char_dict)

#将对应字典频数转化为概率值
def calPercent_dict(input_dict):
    
    valueTotal = 0    
    for value in input_dict.values():
        valueTotal += value
#    print(valueTotal)
    
    Percentdict = input_dict 
    for item in Percentdict:
        Percentdict[item] = Percentdict[item]/valueTotal
    
    TopPercentdict = sorted(Percentdict.items(), key = lambda item : item[1],reverse=True)
    return TopPercentdict

def writePercent(Tofile,inputPercentTuple):
    with open(Tofile,'w') as fp:     
        fp.write('\n'.join('%s %s' % x for x in inputPercentTuple))
    fp.close()
    
def strAnalysis(passwdfile):
    
    fp_passwd = open(passwdfile,'r')
    
    #字符串_结构字典
    struct_dict = {}
    
    #字符串_字母字典
    alpha_dict = {}
    
    #字符串_数字字典
    digit_dict = {}
    
    #字符串_字符字典
    char_dict = {}
    
    
    for each_line in fp_passwd:
        #删除头尾空白字符
        each_line = each_line.strip()
        
        NewSign = sign = ''
        count = 0        
        structStr = ''
        ch_str = ''
        
        #挨个读取字符进行结构分析
        for i in range(len(each_line)):
            if each_line[i].isalpha():
                sign = 'L'       
            elif each_line[i].isdigit():
                sign = 'D'   
            else:
                sign = 'S'
                
            count += 1
                
            #处理第一个字符的newsign与sign之间的矛盾   
            if i == 0:
                NewSign = sign
    
            if NewSign == sign:
                ch_str += each_line[i]
                
            else :
                struct = NewSign + str(count-1)    
                structStr += struct
                count = 1
                alpha_dict,digit_dict,char_dict = add_dict(NewSign,ch_str,alpha_dict,digit_dict,char_dict)
                ch_str = each_line[i]
    
            NewSign = sign
        
        #拼接结构串
        struct = sign + str(count)    
        structStr += struct

        #将字符串结构加入结构字典
        if structStr in struct_dict:
            struct_dict[structStr] += 1
        else :
            struct_dict[structStr] = 1
        
        #将密码字符片段加入对应字典
        alpha_dict,digit_dict,char_dict = add_dict(NewSign,ch_str,alpha_dict,digit_dict,char_dict)
            
    #将各个字典value频数转化为概率值，并按照倒叙排列
    TopPercent_struct =  calPercent_dict(struct_dict)
    TopPercent_alpha =  calPercent_dict(alpha_dict)       
    TopPercent_digit =  calPercent_dict(digit_dict)  
    TopPercent_char =  calPercent_dict(char_dict)
    return (TopPercent_struct,TopPercent_alpha,TopPercent_digit,TopPercent_char)
    
if __name__ == '__main__':
    passwdfile = 'D:\\spyProject\\data\\web\\allPass.txt'
    struct_file = 'D:\\spyProject\\data\\web\\passwd_struct.txt'
    alpha_file = 'D:\\spyProject\\data\\web\\passwd_alpha.txt'
    digit_file = 'D:\\spyProject\\data\\web\\passwd_digit.txt'
    char_file = 'D:\\spyProject\\data\\web\\passwd_char.txt'
    print("come on baby!")
    TopPercent_struct,TopPercent_alpha,TopPercent_digit,TopPercent_char = strAnalysis(passwdfile)
    for (Tofile,inputPercentTuple) in [(struct_file,TopPercent_struct),(alpha_file,TopPercent_alpha),(digit_file,TopPercent_digit),(char_file,TopPercent_char)]:
        writePercent(Tofile,inputPercentTuple)
    