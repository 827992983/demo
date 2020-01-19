实现的功能:读取 64位/32位 elf文件,打印section,segments,sectiom to segments mapping

使用方法: 文件夹里面有一个 readelf 文件,这时已经编译好的程序,然后还有一个 elfcase64 和 elfcase32 测试文件
		 使用的方法是 :  ./readelf elfcase64  
			or    :  ./readelf /usr/bin/gdb 

开发和测试环境: centos 7
