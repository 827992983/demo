EasyHookDemo是一个EasyHook的使用例子： 

1.messagebox_hook_dll是一个dll，用于注入某个进行

2.target_app是目标进程，该进程调用了MessageBox函数 

3.inject_test是测试注入，执行inject_test.exe会把messagebox_hook_dll.dll注入到目标进程target_app.exe

4.inject_tool是注入工具，以后开发其他dll，直接使用这个工具就可以把dll注入到目标进程，该工具支持两种注入方式：

    inject_tool.exe --process-id 16080 --module-name messagebox_hook_dll.dll --inject
    
    inject_tool.exe --process-name target_app.exe --module-name messagebox_hook_dll.dll --inject

测试：

1.先执行target_app.exe，点击"Click Me"按钮，会弹出MessageBox对话框，显示内容："I am system MessageBox." 

2.再执行target_app.exe或inject_tool.exe命令(带上必要参数) 

3.在点击target_app.exe的"Click Me"按钮，会弹出MessageBox对话框，显示内容："You are changed." 

