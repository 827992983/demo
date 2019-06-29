#include "stdafx.h"
#include "IOCPServer.h"
#include <process.h>
#include <stdio.h>
#include <tchar.h>
#include "Lock.h"

CRITICAL_SECTION CIOCPServer::m_cs;

CIOCPServer::CIOCPServer()
{
	m_hShutDownEvent = NULL;
	m_hIOCompletionPort = NULL;
	m_nThreadCnt = 0;
	m_pWorkThreads = NULL;
	m_nPort = 0;
	m_lpfnAcceptEx = NULL;
	m_pListenContext = new PER_IO_CONTEXT;
	m_nKeepLiveTime = 1000 * 60 * 3; // 三分钟探测一次
	m_pListenIocpParam = new IOCP_PARAM;
}


CIOCPServer::~CIOCPServer()
{
}

bool CIOCPServer::StartIOCP(NOTIFYPROC pNotifyProc, const UINT& nPort)
{
	m_nPort = nPort;
	m_pNotifyProc = pNotifyProc;
	InitializeCriticalSection(&m_cs);
	
	bool bRet = false;
	do 
	{
		if (NULL == (m_hShutDownEvent = CreateEvent(NULL, TRUE, FALSE, NULL)))
			break;
		if (!InitNetEnvironment())
			break;
		if (!InitializeIOCP())
			break;
		if (!InitializeListenSocket())
			break;
		bRet = true;
	} while (FALSE);
	
	if (!bRet)
	{
		TCHAR szErr[32];
		_stprintf(szErr, _T("Error code:%d"), GetLastError());
		::MessageBox(GetDesktopWindow(), szErr, L"启动服务器失败", MB_OK | MB_ICONHAND);
	}
	
	return bRet;
}

bool CIOCPServer::Stop()
{
	if (m_socListen != INVALID_SOCKET)
	{
		SetEvent(m_hShutDownEvent);

		for (unsigned int i = 0; i < m_nThreadCnt; i++)
		{
			PostQueuedCompletionStatus(m_hIOCompletionPort, 0, (DWORD)EXIT_CODE, NULL);
		}

		WaitForMultipleObjects(m_nThreadCnt, m_pWorkThreads, TRUE, INFINITE);

		ReleaseResource();
	}
	return true;
}

bool CIOCPServer::InitNetEnvironment()
{
	WSADATA wsaData;
	if (0 != WSAStartup(MAKEWORD(2,2),&wsaData))
		return false;
	return true;
}

bool CIOCPServer::InitializeIOCP()
{
	SYSTEM_INFO systemInfo;
	UINT nThreadID;

	// 创建完成端口
	m_hIOCompletionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (NULL == m_hIOCompletionPort)
		return false;
	
	GetSystemInfo(&systemInfo);
	// 线程数的限制，防止线程上下文切换浪费资源
	m_nThreadCnt = WORKER_THREADS_PER_PROCESSOR * systemInfo.dwNumberOfProcessors + 2;// 核心数的两倍+2

	m_pWorkThreads = new HANDLE[m_nThreadCnt];
	for (unsigned int i = 0; i < m_nThreadCnt; i++)
	{
		m_pWorkThreads[i] = (HANDLE)_beginthreadex(NULL, 0, ThreadPoolFunc, (void*)this, 0, &nThreadID);
		if (NULL == m_pWorkThreads[i])
		{
			CloseHandle(m_hIOCompletionPort);
			return false;
		}
	}

	return true;
}

bool CIOCPServer::InitializeListenSocket()
{
	// AcceptEx 和 GetAcceptExSockaddrs 的GUID，用于导出函数指针
	GUID GuidAcceptEx = WSAID_ACCEPTEX;
	GUID GuidGetAcceptExSockAddrs = WSAID_GETACCEPTEXSOCKADDRS;

	// 需要使用重叠IO，必须使用WSASocket来建立Socket，才可以支持重叠IO操作
	m_socListen = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_IP, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (INVALID_SOCKET == m_socListen)
		return false;

	m_pListenIocpParam->m_sock = m_socListen;
	// 将 监听套接字 绑定到完成端口中
	if (!AssociateSocketWithCompletionPort(m_socListen,(DWORD)m_pListenIocpParam))
	{
		RELEASE_SOCKET(m_socListen);
		return false;
	}

	// 绑定
	SOCKADDR_IN servAddr;
	ZeroMemory(&servAddr, sizeof(SOCKADDR_IN));
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
	servAddr.sin_port = htons(m_nPort);
	if (SOCKET_ERROR == bind(m_socListen,(struct sockaddr*)&servAddr,sizeof(servAddr)))
	{
		RELEASE_SOCKET(m_socListen);
		return false;
	}

	// 开始监听
	if (SOCKET_ERROR == listen(m_socListen,SOMAXCONN))
	{
		RELEASE_SOCKET(m_socListen);
		return false;
	}

	// 使用AcceptEx函数，因为这个是属于WinSock2规范之外的微软另外提供的扩展函数
	// 所以需要额外获取一下AcceptEx函数的指针
	DWORD dwBytes = 0;
	if (SOCKET_ERROR == WSAIoctl(
		m_socListen,
		SIO_GET_EXTENSION_FUNCTION_POINTER,
		&GuidAcceptEx, sizeof(GuidAcceptEx),
		&m_lpfnAcceptEx, sizeof(m_lpfnAcceptEx),
		&dwBytes, NULL, NULL))
	{
		this->ReleaseResource();
		return false;
	}

	// 获取GetAcceptExSockAddrs函数指针，也是同理
	if (SOCKET_ERROR == WSAIoctl(
		m_socListen,
		SIO_GET_EXTENSION_FUNCTION_POINTER,
		&GuidGetAcceptExSockAddrs,
		sizeof(GuidGetAcceptExSockAddrs),
		&m_lpfnGetAcceptExSockAddrs,
		sizeof(m_lpfnGetAcceptExSockAddrs),
		&dwBytes,
		NULL,
		NULL))
	{
		this->ReleaseResource();
		return false;
	}

	// 为AcceptEx 准备参数，然后投递AcceptEx I/O请求
	for (int i = 0; i < MAX_POST_ACCEPT; i++)
	{
		PER_IO_CONTEXT* pAcceptIoContext = new PER_IO_CONTEXT;
		pAcceptIoContext->Clear();
		if (FALSE == PostAcceptEx(pAcceptIoContext))
		{
			this->RemoveStaleClient(pAcceptIoContext,TRUE);
			this->ReleaseResource();
			return false;
		}
		m_listAcceptExSock.push_back(pAcceptIoContext);
	}

	return true;
}


bool CIOCPServer::PostAcceptEx(PER_IO_CONTEXT* pAcceptIoContext)
{
	pAcceptIoContext->m_ioType = IOAccept;// 初始化 IO类型 为接收套接字

	// 为以后新连入的客户端准备好Socket（这是与传统Accept最大的区别）
	// 实际上市创建一个 网络连接池 ，类似于 内存池，我们先创建一定数量的socket，然后直接使用就是了
	pAcceptIoContext->m_sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_IP, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (INVALID_SOCKET == pAcceptIoContext->m_sock)
		return false;

	// 投递异步 AcceptEx
	if (FALSE == m_lpfnAcceptEx(
		m_socListen,
		pAcceptIoContext->m_sock,
		pAcceptIoContext->m_wsaBuf.buf,
		pAcceptIoContext->m_wsaBuf.len - ((sizeof(SOCKADDR_IN) + 16) * 2),
		sizeof(SOCKADDR_IN) + 16,
		sizeof(SOCKADDR_IN) + 16,
		&(pAcceptIoContext->m_dwBytesRecv),
		&(pAcceptIoContext->m_ol))
		)
	{
		if (WSA_IO_PENDING != WSAGetLastError())
			return false;
	}

	return true;
}

unsigned __stdcall CIOCPServer::ThreadPoolFunc(LPVOID lpParam)
{
	CIOCPServer* pThis = (CIOCPServer*)lpParam;
	OVERLAPPED*	pOverlapped = NULL;
	DWORD dwIoSize = 0;
	BOOL bRet = FALSE;
	DWORD dwErr = 0;
	IOCP_PARAM* pIocpParam = NULL;
	PER_IO_CONTEXT* pIoContext = NULL;

	// 循环处理，直到 退出事件 有信号到来，就进行退出
	while (WAIT_OBJECT_0 != WaitForSingleObject(pThis->m_hShutDownEvent, 10))
	{
		bRet = GetQueuedCompletionStatus(//  从完成端口中获取消息
			pThis->m_hIOCompletionPort,
			&dwIoSize,
			(PULONG_PTR)&pIocpParam,
			&pOverlapped,
			INFINITE);

		if (EXIT_CODE == pIocpParam)
			break;

		pIoContext = CONTAINING_RECORD(pOverlapped, PER_IO_CONTEXT, m_ol);

		if (!bRet)// 处理错误信息
		{
			dwErr = GetLastError();
			if (WAIT_TIMEOUT == dwErr)// 超时
			{
				// 超时后，通过发送一个消息，判断是否断线，否则在socket上投递WSARecv会出错
				// 因为如果客户端网络异常断开(例如客户端崩溃或者拔掉网线等)的时候，服务器端是无法收到客户端断开的通知的
				if (-1 == send(pIocpParam->m_sock, "", 0, 0))
				{
					pThis->MoveToFreeParamPool(pIocpParam);
					pThis->RemoveStaleClient(pIoContext,FALSE);
				}
				continue;
			}
			if(ERROR_NETNAME_DELETED == dwErr)// 客户端异常退出
			{
				pThis->MoveToFreeParamPool(pIocpParam);
				pThis->RemoveStaleClient(pIoContext, FALSE);
				continue;
			}
	
			break;// 完成端口出现错误
		}
	
		// 正式处理接收到的数据 读取接收到的数据
		// CONTAINING_RECORD宏返回给定结构类型的结构实例的 基地址 和包含结构中字段的地址。
		if (bRet && 0 == dwIoSize)
		{
			// 客户端断开连接，释放资源
			pThis->MoveToFreeParamPool(pIocpParam);
			pThis->RemoveStaleClient(pIoContext, FALSE);
			continue;
		}

		if (bRet && NULL != pIoContext && NULL != pIocpParam)
		{
			try
			{
				//pThis->ParsePacket(pIoContext);
				pThis->ProcessIOMessage(pIoContext->m_ioType, pIoContext, dwIoSize);
			}
			catch (...) {}
		}
	}
	return 0;
}

// 接收到客户端的连接
bool CIOCPServer::OnAccept(PER_IO_CONTEXT* pIoContext)
{
	SOCKADDR_IN* RemoteSockAddr = NULL;
	SOCKADDR_IN* LocalSockAddr = NULL;
	int nLen = sizeof(SOCKADDR_IN);

	///////////////////////////////////////////////////////////////////////////
	// 1. m_lpfnGetAcceptExSockAddrs 取得客户端和本地端的地址信息 与 客户端发来的第一组数据
	// 如果客户端只是连接了而不发消息，是不会接收到的
	this->m_lpfnGetAcceptExSockAddrs(
		pIoContext->m_wsaBuf.buf,						// 第一条信息
		pIoContext->m_wsaBuf.len - ((nLen + 16) * 2),
		nLen + 16, nLen + 16,
		(sockaddr**)&LocalSockAddr, &nLen,				// 本地信息
		(sockaddr**)&RemoteSockAddr, &nLen);			// 客户端信息
	
	//由于这里传入的这个是ListenSocket上的Context，这个Context还需要用于监听下一个链接，
	//所以要将ListenSocket上的Context复制出来一份，为新连入的Socket新建一个SocketContext
	PER_IO_CONTEXT* pNewIoContext = AllocateClientIOContext();
	pNewIoContext->m_sock = pIoContext->m_sock;
	memcpy(&pNewIoContext->m_addr,RemoteSockAddr,sizeof(SOCKADDR_IN));

	// 处理消息，此处为连接上，第一次接受到客户端的数据
	m_pNotifyProc(NULL, pIoContext, NC_CLIENT_CONNECT);

	IOCP_PARAM* pIocpParam = AllocateIocpParam();
	pIocpParam->m_sock = pNewIoContext->m_sock;
	// 将新连接的客户端的socket，绑定到完成端口
	if (!AssociateSocketWithCompletionPort(pNewIoContext->m_sock,(DWORD)pIocpParam))
	{
		closesocket(m_socListen);
		closesocket(pNewIoContext->m_sock);

		delete pNewIoContext;
		delete pIocpParam;
		pNewIoContext = NULL;
		pIocpParam = NULL;
		return false;
	}

	// Set KeepAlive 设置心跳包，开启保活机制，用于保证TCP的长连接（它会在底层发一些数据，不会传到应用层）
	unsigned long chOpt = 1;
	if (SOCKET_ERROR == setsockopt(pNewIoContext->m_sock,SOL_SOCKET,SO_KEEPALIVE,(char*)&chOpt,sizeof(char)))
	{
		// 心跳激活失败
		MoveToFreeParamPool(pIocpParam);
		RemoveStaleClient(pNewIoContext,TRUE);
		return false;
	}

	// 设置超时详细信息
	tcp_keepalive	klive;
	klive.onoff = 1; // 启用保活
	klive.keepalivetime = m_nKeepLiveTime;
	klive.keepaliveinterval = 1000 * 10; // 重试间隔为10秒 Resend if No-Reply
	WSAIoctl
	(
		pNewIoContext->m_sock,
		SIO_KEEPALIVE_VALS,
		&klive,
		sizeof(tcp_keepalive),
		NULL,
		0,
		(unsigned long *)&chOpt,
		0,
		NULL
	);

	// 给新连接的套接字投递接收操作
	if (!PostRecv(pNewIoContext))
	{
		MoveToFreeParamPool(pIocpParam);
	}

	CLock cs(m_cs, "OnAccept");

	pIoContext->Clear();		// 再次初始化，便于再次利用
	return PostAcceptEx(pIoContext);
}



bool CIOCPServer::OnClientAccept(PER_IO_CONTEXT* pIOContext, DWORD dwSize /*= 0*/)
{
	bool bRet = false;
	try
	{
		pIOContext->m_dwBytesRecv = dwSize;
		// ... 处理一些接收到的操作
		bRet = OnAccept(pIOContext);
	}
	catch (...) {}

	return bRet;
}

bool CIOCPServer::OnClientReading(PER_IO_CONTEXT* pIOContext, DWORD dwSize /*= 0*/)
{
	CLock cs(m_cs, "OnClientReading");
	bool bRet = false;
	try
	{
		// 处理接收到的数据
		m_pNotifyProc(NULL, pIOContext, NC_RECEIVE);

		// 再投递一个异步接收消息
		bRet = PostRecv(pIOContext);
	}
	catch (...){}

	return bRet;
}

bool CIOCPServer::PostRecv(PER_IO_CONTEXT* pIoContext)
{
	// 清空缓冲区，再次投递
	ZeroMemory(pIoContext->m_szBuf, MAX_BUFFER_LEN);
	ZeroMemory(&pIoContext->m_ol, sizeof(OVERLAPPED));
	pIoContext->m_ioType = IORecv;
	DWORD dwNumBytesOfRecvd;

	ULONG ulFlags = 0/*MSG_PARTIAL*/;
	UINT nRet = WSARecv(
		pIoContext->m_sock,
		&(pIoContext->m_wsaBuf),
		1,
		&dwNumBytesOfRecvd,// 接收的字节数，异步操作的返回结果一般为0，具体接收到的字节数在完成端口获得
		&(ulFlags),
		&(pIoContext->m_ol),
		NULL);
	if (SOCKET_ERROR == nRet && WSA_IO_PENDING != WSAGetLastError())
	{
		RemoveStaleClient(pIoContext, FALSE);
		return false;
	}
	return true;
}


bool CIOCPServer::OnClientWriting(PER_IO_CONTEXT* pIOContext, DWORD dwSize /*= 0*/)
{
	bool bRet = false;
	try 
	{
		// 异步发送的返回的传输成功的结果是否 少于 要求发送的数据大小（未发送完成），此时重发
		// 最好使用CRC校验之内的，更加严谨性（可以在结构体中放一个计算的CRC值），但是计算会更消耗性能
		if (dwSize != pIOContext->m_dwBytesSend)
		{
			bRet = PostSend(pIOContext);
		}
		else// 已经发送成功，将结构体放回内存池
		{
			m_pNotifyProc(NULL, pIOContext, NC_TRANSMIT);
			MoveToFreePool(pIOContext);
		}
	}
	catch (...) {}

	return bRet;
}



bool CIOCPServer::PostSend(PER_IO_CONTEXT* pIoContext)
{
	pIoContext->m_wsaBuf.buf = pIoContext->m_szBuf;
	pIoContext->m_wsaBuf.len = strlen(pIoContext->m_szBuf);
	pIoContext->m_ioType = IOSend;
	ULONG ulFlags = MSG_PARTIAL;

	INT nRet = WSASend(
		pIoContext->m_sock,
		&pIoContext->m_wsaBuf,
		1,
		&(pIoContext->m_wsaBuf.len),
		ulFlags,
		&(pIoContext->m_ol),
		NULL);
	if (SOCKET_ERROR == nRet && WSA_IO_PENDING != WSAGetLastError())
	{
		RemoveStaleClient(pIoContext, FALSE);
		return false;
	}
	return true;
}

bool CIOCPServer::AssociateSocketWithCompletionPort(SOCKET socket, DWORD dwCompletionKey)
{
	// 绑定套接字绑定到完成端口
	// 第二个参数为完成端口句柄时，返回值为完成端口。为空时，返回新的完成端口句柄
	HANDLE hTmp = CreateIoCompletionPort((HANDLE)socket, m_hIOCompletionPort, dwCompletionKey, 0);
	return hTmp == m_hIOCompletionPort;
}


PER_IO_CONTEXT* CIOCPServer::AllocateClientIOContext()
{
	CLock cs(this->m_cs, "AllocateSocketContext");

	PER_IO_CONTEXT* pIoContext = NULL;
	if (!m_listFreeIoContext.empty())
	{
		pIoContext = m_listFreeIoContext.front();
		m_listFreeIoContext.remove(pIoContext);
	}
	else
	{
		pIoContext = new PER_IO_CONTEXT;
	}
	
	m_listIoContext.push_back(pIoContext);
	if (pIoContext != NULL)//一般都是被清空了的
	{
		// 此处待测试
		pIoContext->Clear();
	}

	return pIoContext;
}


IOCP_PARAM* CIOCPServer::AllocateIocpParam()
{
	CLock cs(m_cs, "AllocateIocpParam");

	IOCP_PARAM* pIocpParam = NULL;
	if (!m_listFreeIocpParam.empty())
	{
		pIocpParam = m_listFreeIocpParam.front();
		m_listFreeIocpParam.remove(pIocpParam);
	}
	else
	{
		pIocpParam = new IOCP_PARAM;
	}

	m_listIocpParam.push_back(pIocpParam);
	if (pIocpParam != NULL)
	{
		pIocpParam->m_sock = INVALID_SOCKET;
	}
	return pIocpParam;
}

VOID CIOCPServer::RemoveStaleClient(PER_IO_CONTEXT* pIoContext, BOOL bGraceful/*是否中止连接*/)
{
	CLock cs(m_cs, "RemoveStaleClient");

	LINGER lingerStruct;

	// 如果我们要中止连接，设置延时值为 0 (优雅的关闭连接)
	if (!bGraceful)
	{
		//.l_onoff=1;（在closesocket()调用,但是还有数据没发送完毕的时候容许逗留)
		// 如果.l_onoff=0;则功能和2.)作用相同;
		lingerStruct.l_onoff = 1;	//开关，零或者非零 
		lingerStruct.l_linger = 0;  //优雅关闭最长时限（允许逗留的时限 秒）
		setsockopt(pIoContext->m_sock, SOL_SOCKET, SO_LINGER,
			(char*)&lingerStruct, sizeof(lingerStruct));
	}

	// 释放 PER_SOCKET_CONTEXT 中的数据
	std::list<PER_IO_CONTEXT*>::iterator iter;
	iter = find(m_listIoContext.begin(), m_listIoContext.end(), pIoContext);
	if (iter != m_listIoContext.end())
	{
		// CancelIo 取消挂起的IO操作 优雅的关闭这个套接字句柄
		CancelIo((HANDLE)pIoContext->m_sock);

		closesocket(pIoContext->m_sock);
		pIoContext->m_sock = INVALID_SOCKET;

		// 判断是否还在进行IO操作 等待上一个IO操作完成再关闭
		while (!HasOverlappedIoCompleted((LPOVERLAPPED)pIoContext))
			Sleep(0);

		// 回调函数，发送退出消息
		m_pNotifyProc(NULL, pIoContext, NC_CLIENT_DISCONNECT);

		MoveToFreePool(pIoContext);
	}
}


VOID CIOCPServer::MoveToFreeParamPool(IOCP_PARAM* pIocpParam)
{
	CLock cs(m_cs, "MoveToFreeParamPool");

	IocpParamList::iterator iter;
	iter = find(m_listIocpParam.begin(), m_listIocpParam.end(), pIocpParam);
	if (iter != m_listIocpParam.end())
	{
		m_listFreeIocpParam.push_back(pIocpParam);
		m_listIocpParam.remove(pIocpParam);
	}
}

VOID CIOCPServer::MoveToFreePool(PER_IO_CONTEXT* pIoContext)
{
	CLock cs(m_cs, "MoveToFreePool");

	IOContextList::iterator iter;
	iter = find(m_listIoContext.begin(), m_listIoContext.end(), pIoContext);

	if (iter != m_listIoContext.end())
	{
		m_listFreeIoContext.push_back(pIoContext);// 不释放已经创建的，加入到内存池中，下次有新客户端连接就不用再创建
		m_listIoContext.remove(pIoContext);
	}
}


VOID CIOCPServer::ReleaseResource()
{
	// 删除关键段
	DeleteCriticalSection(&m_cs);

	// 释放 系统退出事件句柄
	RELEASE_HANDLE(m_hShutDownEvent);

	// 释放工作者线程句柄指针
	for (unsigned int i = 0; i < m_nThreadCnt; i++)
	{
		RELEASE_HANDLE(m_pWorkThreads[i]);
	}
	RELEASE(m_pWorkThreads);

	// 关闭IOCP句柄
	RELEASE_HANDLE(m_hIOCompletionPort);

	// 关闭监听套接字
	RELEASE_SOCKET(m_socListen);


	// 删除监听套接字的完成端口参数
	delete m_pListenIocpParam;

	IOContextList::iterator iter;

	// 清理空闲的套接字
	iter = m_listFreeIoContext.begin();
	while (iter != m_listFreeIoContext.end())
	{
		delete *iter;
		++iter;
	}
	m_listFreeIoContext.clear();

	// 清理连接的套接字
	iter = m_listIoContext.begin();
	while (iter != m_listIoContext.end())
	{
		closesocket((*iter)->m_sock);
		delete *iter;
		++iter;
	}
	m_listIoContext.clear();

	// 清理预创建的套接字
	iter = m_listAcceptExSock.begin();
	while (iter != m_listAcceptExSock.end())
	{
		delete *iter;
		++iter;
	}
}
void CIOCPServer::ParsePacket(PER_IO_CONTEXT* pIoContext)
{
	if (pIoContext == NULL)
	{
		return;
	}
	memset(m_sBuff, 0, sizeof(m_sBuff));
	memcpy(m_sBuff, pIoContext->m_szBuf, pIoContext->m_ol.InternalHigh);
	memset(pIoContext->m_szBuf, 0, sizeof(pIoContext->m_szBuf));
	memcpy( pIoContext->m_szBuf, m_sBuff, pIoContext->m_ol.InternalHigh);

}
