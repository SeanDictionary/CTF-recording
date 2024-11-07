# 0xGame-2024-BlockChain

## [Week 1] 肘，上链！

* 区块链是新方向，可查阅的资料少，难度也大
* 本人做题参考了其他类似的题的wp
* SHCTF-2023-[WEEK2]blockchain signin-[链接](https://blog.csdn.net/Nanian233/article/details/134053768#:~:text=%E2%80%8D%E4%B8%AD%E7%A7%91%E9%87%91%E8%B4%A2%E5%8C%BA)
* 以下是做题时的个人解读

<details class="wp-block-details"><summary>身为小白，你需要知道的东西</summary>

钱包：这是用来装钱的地方，为了方便在浏览器上连接你的钱包建议安装[MetaMask插件(Chrome)](https://chromewebstore.google.com/detail/metamask/nkbihfbeogaeaoehlefnkodbefgpgknn?hl=zh-CN&utm_source=ext_sidebar)

小狐狸：即指MetaMask

水龙头：用于领取**测试用途**的以太币（ETH）

接水：指在水龙头下接水即领取以太币这一操作

燃油费：也称为gas，你执行的每一步操作都要收取一定的燃油费，因而要保证有足够的燃油费来支付你的操作。另外燃油费和以太币可以互相转化

</details>

* nc 连接靶机，靶机输出

```
Can you make the isSolved() function return true?

[1] - Create an account which will be used to deploy the challenge contract
[2] - Deploy the challenge contract using your generated account
[3] - Get your flag once you meet the requirement
[4] - Show the contract source code

'''
你能让isSolved（）函数返回true吗？

[1] - 创建一个用于部署挑战合约的账户
[2] - 使用您生成的账户部署挑战合约
[3] - 满足要求后获取您的国旗
[4] - 显示合约源代码
'''
```

* 题目目的是让isSloved函数返回True
* 先在靶机中输入1，获得**账户**和 **token** =（token千万不能忘，是用来在靶机上身份识别的）=
* 靶机输出 `[+] please transfer more than 0.001 test ether to the deployer account for next step`这里选择转钱或者接水都可以
* 先进入自己安装好的MetaMask

![](https://seandictionary.top/wp-content/uploads/2024/10/image-9.png)

* 点击红框进去后添加网络>手动添加网络

![](https://seandictionary.top/wp-content/uploads/2024/10/image-11.png)

* 名称随意，RPC URL填题干所给，ID随意（之后会出错，填写所给的正确的就行），货币符号随意（一般填ETH）
* 添加完成网络后，进入题干所给的第三个链接faucet（水龙头）浏览器访问
* 在水龙头页面下填入自己钱包的地址（可以从MetaMask查看是否成功到账）以及靶机上给出的地址（若不填靶机地址可以选择转钱给靶机地址>0.001ETH）
* 以上是准备内容，接下来开始部署
* 可以选择网页端-Remix IDE或者脚本-web3
* 下面选择[Remix IDE](https://remix.ethereum.org/)
* 先在靶机上输入2获得合约地址（如果没有，显示的仍是1输出的账户，请查看是否有正确转钱或者接水）
* 靶机上输入4获得源码
* 打开[Remix IDE](https://remix.ethereum.org/)新建文件后缀名为sol，将源码内容复制进去
* 在页面左侧打开编译器，选择对应源码开头的版本，启动编译
* 在页面左侧打开部署&发交易，上方环境选择MetaMask（如果没有，查看是否正确安装插件）
* 连接账户的时候应当会自动弹出插件窗口，输入密码即可连接（如果没有弹出，请手动打开插件查看连接情况）

![](https://seandictionary.top/wp-content/uploads/2024/10/image-12.png)

* 将At Adress处的输入框内容填上靶机给出的合约地址，按下按钮

![](https://seandictionary.top/wp-content/uploads/2024/10/image-13.png)

* 此时可以在边栏最下方看到已部署合约，展开
* 这里sign要求输入，我们开始分析源码

```
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

contract Signin {
    bytes32 signin;

    constructor() {}

    function sign(bytes32 _signin) public {
        signin = _signin;
    }

    function isSolved() public view returns (bool) {
        string memory expected = "Hello0xBlockchain";
        return keccak256(abi.encodePacked(expected)) == signin;
    }
}
```

* 源码定义了一个类型为Byte32的变量用来sign输入，最终传递到signin
* isSolved执行了判断语句，用来比较signin与经过加密后的expected
* 若要输出True，则用工具计算出经过keccak256哈希的结果
* 0x83c9a53a09792c2f7d6d0b19bede7af634e365c92cb3874761e2f0ac2f31bd6a
* 输入后isSolved检验是否返回True
* 最后sign，小狐狸会弹出交易窗口，选择确定，支付燃油费
* 最终回到靶机输入3获得flag
* 0xGame{T3st1ng_ur_bl0ckcha1n!}
