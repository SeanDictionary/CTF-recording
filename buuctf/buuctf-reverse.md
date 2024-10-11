# BUUCTF-REVERSE


## 1.easyre

* IDA打开
* F5得到源码
* 可以得到源程序的逻辑处理
* 得到flag{this_Is_a_EaSyRe}

## 2.reverse1

* IDA打开
* shift+F12查看字符串
* 进入right flag的函数模块
* 分析函数发现，strncmp是c库函数中用来比较的函数
* `Line28.  if ( !strncmp(Str1, Str2, v2) )`
* 当str1与str2相同时输出right flag
* str1是输入，str2是已有字符串
* 双击str2能看见对应的字符串内容{hello_world}
* 继续分析函数

![](https://seandictionary.top/wp-content/uploads/2024/10/image-1.png)

* 这里对str2进行了变换
* 将111换成了48，即o变为了0，在IDA中点击数字按下R可以转化为字符
* 得到flag{hell0_w0rld}

## 3.reverse2

* IDA打开查字符串直接发现了flag
* 但这肯定不是正确的
* 查看伪c代码，发现对flag进行了替换将i和r换成了1
* 最终得到flag{hack1ng_fo1_fun}

## 4.内涵的软件

* IDA打卡，发现主函数直接返回了另一个函数
* 继续查看内嵌函数
* 发现类似flag的内容，尝试提交，成功
* flag{49d3c93df25caad81232130f3d2ebfad}

![](https://seandictionary.top/wp-content/uploads/2024/10/image-17.png)
