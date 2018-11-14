# WebSecurity_Passwd使用说明

WebSecurity_Passwd工程包含四种口令分析方式并分别生成四种模式的口令字典，包括结构、键盘、日期、英文单词四种生成模式，用户可以选择任意生成模式进行口令字典生成，生成算法采用PCFG算法。分析口令的数据集来自csdn和yahoo的口令数据集`www.csdn.net.sql`和`plaintxt_yahoo.txt`。

## 总程序入口

为便于用户输入，我们准备了额外的总程序入口方便用户输入，在命令行下输入用户可选择生成字典容量及生成模式完成口令生成任务。

### 准备工作

如需生成结构模式的口令字典，需首先将`.\structure\spyProject.rar`文件解压缩至`D:\\`根目录下以备结构文件及字典生成，解压示例如`.\structure\spyProjectSample.rar`

### 获取帮助信息

```
> python WebSecurity_Passwd.py -h
usage: WebSecurity_Passwd.py [-h] [-n NUMBER] [-p PATTERN]

optional arguments:
  -h, --help            show this help message and exit
  -n NUMBER, --number NUMBER
                        determine the number of generation password
  -p PATTERN, --pattern PATTERN
                        choose the string of the generation pattern including
                        's': structure, 'k': keyboard, 'd': date, 'w': words,
                        'a': all pattern combination

```

打开`cmd`在终端下执行`WebSecurity_Passwd.py`文件，其中`-h`参数表示帮助信息，`-n`参数确定字典中生成口令的数量，`-p`参数选择生成模式，生成模式参数选择如下：

* `s`为结构口令生成模式
* `k`为键盘口令生成模式
* `d`为日期口令生成模式
* `w`为英文单词口令生成模式
* `a`为选择所有模式顺序生成口令字典文件，每个口令字典生成数量等于用户输入的`-n`参数数量。

### 开始执行

在`cmd`下执行命令如下：

```
> python WebSecurity_Passwd.py -n 10000 -p k
```

示例表示选择键盘模式`k`生成包含`10000`条口令的口令字典，生成的口令字典文件分别在四种模式文件夹下生成，其路径分别为:

* 结构口令字典

  `D:\spyProject\data\web\mxm_genPasswordResult.txt`

* 键盘口令字典

  `.\keyboard\generation_csdn_keyboard_passwd_dict.txt` `.\keyboard\generation_yahoo_passwd_keyboard_dict.txt`

* 日期口令字典

  `.\date\generation_csdn_date_passwd_dict.txt`

  `.\date\generation_yahoo_date_passwd_dict.txt`

* 英文单词口令字典

  `.\word\csdn\generation_csdn_passwd_keyboard_dict.txt`

  `.\word\yahoo\generation_yahoo_passwd_keyboard_dict.txt`

## 各个生成模式使用说明

如需在各个模式文件夹下单独执行生成模式文件，可依照此步骤执行。

### structure结构模式

由于程序中牵扯的文件夹较多，所以先行创建了空的文件目录文件`spyProject.rar`和`spyProjectSample.rar`解压到当前文件夹后拷贝到D盘即可操作。`spyProject.rar`为空目录和一些原始文件`spyProjectSample.rar`内包含一些已经分析好的结构文件可用于生成密码。

#### 第一种情况：

如果想要从零开始重新运行程序，请对压缩包`spyProject.rar`选择解压到当前文件夹并拷贝到D盘根目录

* 首先直接运行：`PassWdTotal.py  `

  目标：生成整体密码文件`allPassNew.txt`作为后来分析所用

* 命令行执行`python mxm_structure.py number`(例如 `Python mxm_structure.py 100 `) 

  目标：分析密码文件，生成随机密码文件`mxm_genPasswordResult.txt`

* 直接运行：`mxm_structure_verify.py`(可不运行)

​       目标：对第二步生成的密码进行结构分析得到一系列文件与之前密码库进行验证

#### 第二种情况：

​       如果只是想略过结构分析步骤，直接利用作者之前得到的结构文件进行密码生成，请对压缩包`spyProjectSample.rar`选择解压到当前文件夹并拷贝到D盘根目录，里面存放了用于直接生成密码的文件。

* 将`mxm_structure.py`文件的**380-382行**，**386行**，**398-399行**，**413-414行**注释掉。命令行执行`python mxm_structure.py number`(例如 `Python mxm_structure.py 100` ) 

  目标：根据密码分析文件，直接生成密码

* 直接运行：`mxm_structure_verify.py`(可不运行)

  目标：对第一步生成的密码进行结构分析得到一系列文件与之前密码库进行验证

### keyboard键盘模式

#### 准备工作

工程需要准备`re`和`numpy`库支持，且`python版本`为`python 3.6.5`，并保证数据集文件`www.csdn.net.sql`和`plaintxt_yahoo.txt`存放在`.\keyboard\`目录下。

键盘模式的执行序为：

* 首先匹配键盘模式字符串，获取键盘口令数据集
* 分析键盘模式关键字的概率分布
* 分析键盘模式的结构组合及其概率分布
* 分析各个长度下数字、字母、字符的元素组合概率分布
* 依概率随机生成口令结构并依概率随机填充关键字和各元素组合，生成口令字典

* 用户可在**line 109：**`pattern`列表下存储需要匹配的键盘模式，如第一键盘行``1234567890-=`

#### 开始执行

在`cmd`中输入如下命令:

```> inaafafa
> python keyboard_analyse.py 10000
```

`10000`表示用户希望生成的口令个数，可自行修改。

口令字典分别存储在以下路径下:

`.\keyboard\generation_csdn_keyboard_passwd_dict.txt` `.\keyboard\generation_yahoo_passwd_keyboard_dict.txt`

如需要略过分析步骤，直接执行口令生成算法：

* 将`.\keyboard\keyboard_path_file`下的所有文件放至与`keyboard_analyse.py`同级目录下
* 将**line 750 - line 757**使用`#`注释，略过分析步骤
* 执行`python keyboard_analyse.py 10000`,生成口令数目`10000`可自行选择

### date日期模式

#### 程序声明

程序名：`DKA.py`
程序函数结构树：

``````
main|
  |load_csdn_key,load_yahoo_key[1]
  |Date_Password_Statistics[2]
    |ADK[2.1]
  |Date_pwd_struct_statistics[3]
  |Generate_dict[4]
    random_select[4.1]
``````

#### 函数含义
[1]载入原始口令数据库信息
[2]根据日期正则匹配，对日期口令统计，从原始数据中筛选出日期口令
[3]针对日期口令的组成结构进行分析，分为L（字母）S（特殊字符）D（数字）R（日期）
[4]生成字典
[4.1]对结构进行对应概率分布情况进行选取，对结构组成元素内容进行对应概率分布情况进行选取

#### 使用程序
程序执行需要安装`numpy`、`time`、`re`库。
将原始口令数据库存放到程序所在目录，在`main`函数中设置路径及文件名，执行程序，可从程序执行过程了解执行进度情况。
程序执行过程不需要交互动作，实现预设置的内容均在`main`函数中。

### word英文单词模式

#### 程序功能

* 统计密码中英文单词的使用情况
* 识别密码结构
* 根据密码库统计结果随机生成密码字典

#### 使用说明
运行`yahoo`文件夹的`yahoo_englishword_analysis.py`，即可在当前文件夹中得到相应结果文件：

* `english_word_times.txt `出现在密码中的单词及次数统计文件
* `yahoo_password_position.txt yahoo`密码中出现英文单词的密码及其位置
* `yahoo_structure_p="yahoo_structure_p.txt" `yahoo密码按照结构划分概率文件
* `i_length_englishword.txt yahoo`密码中出现的不同长度英语单词和概率
* `i_length_digital.txt yahoo`密码中出现的不同长度数字组合和概率
* `i_length_language.txt yahoo`密码中出现的不同长度字母组合和概率
* `i_length_string.txt yahoo`密码中出现的不同长度符号组合和概率
* `generation_yahoo_passwd_keyboard_dict.txt` 生成的密码字典

#### 修改文件名
* 其中`english_process.txt`为英语单词

* 若要修改原始文件名，请在`main`函数中`yahoo_data_path`、`english_word_path`修改
* 在命令行执行`.py`后加单词个数，或在文件修改`main`函数的`generate_passwd_number = 10000`变量可更改字典生成规模
* `word_times_path` 出现在密码中的单词及次数统计文件路径
* `yahoo_password_position` yahoo密码中出现英文单词的密码及其位置文件路径
* `yahoo_structure_p` yahoo密码按照结构划分概率文件路径
* `generation_yahoo_passwd_dict_path `生成的密码字典路径

* `csdn`同理
