# -*- coding: utf-8 -*-
"""
Created on Sun Oct 28 10:53:13 2018

@author: mxm
"""

import os
import numpy as np
import re
from tqdm import tqdm

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

#写入对应字符串频率文件
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
        changetime = 0
        
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
                changetime += 1
                struct = NewSign + str(count-1)    
                structStr += struct
                count = 1
                if len(ch_str.split()) != 0:
                    alpha_dict,digit_dict,char_dict = add_dict(NewSign,ch_str,alpha_dict,digit_dict,char_dict)
                ch_str = each_line[i]
                
            NewSign = sign
        
        #全是一类字符的情况
        if changetime == 0:
            struct = NewSign + str(count)    
            structStr += struct
            if len(ch_str.split()) != 0:
                alpha_dict,digit_dict,char_dict = add_dict(NewSign,ch_str,alpha_dict,digit_dict,char_dict)
        
        else:
            #拼接结构串
            struct = sign + str(count)    
            structStr += struct
    
        #将字符串结构加入结构字典
        #if!=0判断，防止读入空白行写入
        if structStr != '0':
            if structStr in struct_dict:
                struct_dict[structStr] += 1
            else :
                struct_dict[structStr] = 1
      
    #将密码字符片段加入对应字典
    if len(ch_str.split()) != 0:
        alpha_dict,digit_dict,char_dict = add_dict(NewSign,ch_str,alpha_dict,digit_dict,char_dict)
        
    #将各个字典value频数转化为概率值，并按照倒序排列
    TopPercent_struct =  calPercent_dict(struct_dict)
    TopPercent_alpha =  calPercent_dict(alpha_dict)       
    TopPercent_digit =  calPercent_dict(digit_dict)  
    TopPercent_char =  calPercent_dict(char_dict)
    return (TopPercent_struct,TopPercent_alpha,TopPercent_digit,TopPercent_char)


#为结构概率文件的各个结构划分0-1数轴空间
def normalizationStructFile(percentfile,addfile):
    percent_add = 0
    with open(percentfile,'r') as fr:
        with open(addfile,'w') as fw:
            while(True):
                line = (fr.readline()).split(' ')
#                print(line)
                
                #判断读到了末尾
                if len(line) == 1:
                    print(addfile+'已写入完成')
                    print('最后一个字符串区间上界为：'+str(percent_add))
                    break
                
                #一般行的格式
                elif len(line) == 2 :
                    char_str = line[0]
                    percent_add += float(line[1])
                    lineList = [char_str,str(percent_add)]
                    fw.write(' '.join(lineList)+'\n')
                    
                else:
                    print('貌似异常！')          
        fw.close()
    fr.close() 

#按照字符串长度将各字符串分开
def filebyLen(originalfile,datadir):
    with open(originalfile,'r') as fr:
        while(True):
            line = (fr.readline()).split(' ')
#                print(line)
            
            #判断读到了末尾
            if len(line) == 1:
                print(originalfile+'整理完成！')
                break
            
            #一般行的格式
            elif len(line) == 2 :
                
                char_str = line[0]
                char_len = len(char_str)
                
                #以字符串长度命名文件
                lenfilename = datadir + str(char_len)+'.txt'
                with open(lenfilename,'a+') as fw:
                    percent = float(line[1])
                    lineList = [char_str,str(percent)]
                    fw.write(' '.join(lineList)+'\n')
                fw.close()
                
            else:
                print('貌似异常！')
                
    fr.close() 

#将各个类别的字符串按照长度文件归一化划分0-1数轴空间   
def normalizationLengthFile(originaldatadir,meddatadir,outdatadir):
    total = 0
    for file in os.listdir(originaldatadir):
        filepercentTotal = 0
        filename = originaldatadir + file
        medfilename = meddatadir + file
        outfilename = outdatadir + file
        
        #计算此文件真实概率之和
        with open(filename,'r') as fr:
            while(True):
              
                line = (fr.readline()).split(' ')
                
                #判断读到了末尾
                if len(line) == 1:
#                    print(originalfile+' 读取完成！')
                    break
                
                elif len(line) == 2:
                    filepercentTotal += float(line[1])
                    
                else:
                    print('貌似异常！')
            
#            print('文件'+filename+ '所占概率为' + str(filepercentTotal))
            fr.close()
        
        #写入中间概率文件（归一化结果）
        with open(filename,'r') as fr:
            with open(medfilename,'w') as fw:
                while(True):
                  
                    line = (fr.readline()).split(' ')
                    
                    #判断读到了末尾
                    if len(line) == 1:
#                        print(medfilename+' 写入完成！')
                        break
                    
                    elif len(line) == 2:
                        char_str = line[0]
                        percent = float(line[1])/filepercentTotal
                        lineList = [char_str,str(percent)]
                        fw.write(' '.join(lineList)+'\n')
                        
                    else:
                        print('貌似异常！')
                
            fw.close()
        fr.close()
        
        #为归一化后的概率文件进行0-1区间划分
        percent_add = 0
        with open(medfilename,'r') as fr:
            with open(outfilename,'w') as fw:
                while(True):
                    line = (fr.readline()).split(' ')
    #                print(line)
                    
                    #判断读到了末尾
                    if len(line) == 1:
#                        print(outfilename+' 写入完成')
#                        print('最后一个字符串区间上界为：'+str(percent_add))
                        break
                    
                    #一般行的格式
                    elif len(line) == 2 :
                        char_str = line[0]
                        percent_add += float(line[1])
                        lineList = [char_str,str(percent_add)]
                        fw.write(' '.join(lineList)+'\n')
                        
                    else:
                        print('貌似异常！')          
            fw.close()
        fr.close() 
 
        total += filepercentTotal
    print(originaldatadir+'   处理完成')
    print('类别文件总概率核对：'+str(total))
            
#生成一个[0,max)的随机数
def genrandValue(seedpoint,maxValue):
    np.random.seed(seedpoint)
    randValue = (np.random.uniform(0.,maxValue,1)) 
    return randValue[0]  

#获取文件0-1区间划分的最大上界值
def fileMax(file):
    maxValue = 0
    with open(file,'r') as fr:
        while(True):
            
            line = fr.readline().split(' ')
            
            if len(line) == 1:
                return maxValue
            
            #一般行的格式
            elif len(line) == 2 :
                #返回最后一个数字即是最大
                maxValue = float(line[1])
                
            else:
                print('貌似异常！') 

#按照随机数的范围返回对应结构
def genString(seedpoint,file,sign):
    stop = 1
    #求取上界
    maxValue = fileMax(file)
    
    #生成随机数
    #if判断为机构做特例
    if sign != '':
        np.random.seed(sign)
        seedpoint = np.random.randint(0,10000)   

    randValue = genrandValue(seedpoint,maxValue)
    
    with open(file,'r') as fr:
        while( stop == 1 ):
            line = fr.readline().split(' ')
            
            if len(line) == 2:
                upvalue = float(line[1])
                
                if  randValue <= upvalue:
#                    print('随机数 '+ str(randValue) + ' <= ' +str(upvalue))
                    stop = 0
                    return line[0]           
    fr.close()

#根据生成的密码结构生成密码  
def genPassword(seed,genstruct,outChar,outAlpha,outDigit):
    genstruct = re.findall(r'([\w])(\d+)*',genstruct)
    seed_num = len(genstruct)
#    print(genstruct)
    genPass = ''
    seed_th = 1
    
    for item in genstruct:
        label = item[0]
        numfile = item[1]
        
        if label == 'L':
            usedatadir = outAlpha
        elif label == 'D':
            usedatadir = outDigit
        else:
            usedatadir = outChar
        
        #为每一个字符串的随机数生成一个随机种子
        np.random.seed(seed)
        seedpoint = np.random.randint(0,10000,size=seed_num+1)    
        
        choosefile = usedatadir + str(numfile) + '.txt'
        genPass += genString(seedpoint[seed_th],choosefile,'')
        seed_th += 1
        
    return genPass
        

        
if __name__ == '__main__':
    
    print("come on baby!")
    
    #密码文件
    passwdfile = 'D:\\spyProject\\data\\web\\verify\\mxm_genPasswordResult.txt'
    
    #各个字符串概率文件
    struct_file = 'D:\\spyProject\\data\\web\\verify\\passwd_structV.txt'
    alpha_file = 'D:\\spyProject\\data\\web\\verify\\passwd_alphaV.txt'
    digit_file = 'D:\\spyProject\\data\\web\\verify\\passwd_digitV.txt'
    char_file = 'D:\\spyProject\\data\\web\\verify\\passwd_charV.txt'
    
    TopPercent_struct,TopPercent_alpha,TopPercent_digit,TopPercent_char = strAnalysis(passwdfile)
    for (Tofile,inputPercentTuple) in [(struct_file,TopPercent_struct),(alpha_file,TopPercent_alpha),(digit_file,TopPercent_digit),(char_file,TopPercent_char)]:
        writePercent(Tofile,inputPercentTuple)
    
    #根据各字符长度生成txt文件
    original_alpha = 'D:\\spyProject\\data\\web\\verify\\passwd_alphaV.txt'
    datadir_alpha = 'D:\\spyProject\\data\\web\\verify\\alphaV\\'
    
    original_digit = 'D:\\spyProject\\data\\web\\verify\\passwd_digitV.txt'
    datadir_digit = 'D:\\spyProject\\data\\web\\verify\\digitV\\'
    
    original_char = 'D:\\spyProject\\data\\web\\verify\\passwd_charV.txt'
    datadir_char = 'D:\\spyProject\\data\\web\\verify\\charV\\'
        
    for (originalfile,datadir) in [(original_alpha,datadir_alpha),(original_digit,datadir_digit),(original_char,datadir_char)]:
        filebyLen(originalfile,datadir) 
    

    print('good job!')