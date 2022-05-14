#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


// SSL初始化所需证书密钥信息
#define HOME	"./cert_hwk/"
#define CERTF	HOME"server.crt"
#define KEYF	HOME"server.key"
#define CACERT	HOME"ca.crt"

// 打印
#define CHK_NULL(x)	if ((x)==NULL) exit (1)
#define CHK_ERR(err,s)	if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err)	if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

typedef struct UserInfo
{
	int id;
	char pipe_path[20];
} UserInfo;

typedef struct TunData
{
	UserInfo* info;
	int tunfd;
}TunData;

typedef struct PipeData
{
	UserInfo* info;
	char* pipe_file;
	SSL* ssl;
}PipeData;

// 初始化
SSL* init_SSL();		// SSL初始化(SSL层)
int init_TCP();			// TCP初始化(socket接口)
int init_TUN();			// Tun初始化(tun0接口)

void select_tun(int tunfd, struct sockaddr_in sockaddr_client, SSL* ssl);		// 发送数据
void select_sock(int tunfd, struct sockaddr_in sockaddr_client, SSL* ssl);		// 接收数据
void select_pipe();

int auth(SSL* ssl);	// 身份认证

void processRequest(fd_set set);

int main()
{
	int err;
	struct sockaddr_in sockaddr_client;
	size_t sockaddr_client_len = sizeof(sockaddr_client);
	UserInfo user_table[20];
	int index = 0;
	memset(user_table, 0, sizeof(user_table));

	// 初始化
	SSL* ssl = init_SSL();
	int server_sock = init_TCP();
	int tunfd = init_TUN();

	// 开辟线程监视tun0
	system("rm -rf pipe");
	mkdir("pipe", 0755);
	pthread_t listen_tun_thread;
	pthread_create(&listen_tun_thread, NULL, listen_tun, (void*)&tunfd);

	// 修改系统配置
	system("sudo ifconfig tun0 192.168.53.1/24 up");
	system("sudo sysctl net.ipv4.ip_forword=1");

	fprintf(stderr, "server_sock = %d\n", server_sock);
	// 主循环
	while (1) {
		// 阻塞等待客户端连接
		int client_sock = accept(server_sock, (struct sockaddr*)&sockaddr_client, &sockaddr_client_len);
		if (client_sock == -1) {
			fprintf(stderr, "[TCP] connect failed! (%d: %s)\n", errno, strerror(errno));
			continue;
		}
		if (fork() == 0) {
			// 子进程
			// 关闭fork产生的server_sock
			// 搭建父子双向管道
			close(server_sock);

			SSL_set_fd(ssl, client_sock);
			int err = SSL_accept(ssl);
			fprintf(stderr, "[SSL] SSL_accept return %d\n", err);
			CHK_SSL(err);
			printf("[SSL] connection established\n");
			// 身份认证
			if (auth(ssl) == 1) {
				user_table[index].id =


					char pipe_path[20];
				sprintf(pipe_path, "./pipe/%s", )

					SSL_shutdown(ssl);
				SSL_free(ssl);
				close(client_sock);
				printf("[Auth] fail\n");
				return 0;
			}

			// 处理请求
			fd_set client_fd_set;
			FD_ZERO(&client_fd_set);
			FD_SET(client_sock, &client_fd_set);
			FD_SET(pipefd[0], &client_fd_set);

			close(client_sock);
			return 0;
		} else {
			// 父进程
			close(client_sock);
		}
	}
}

SSL* init_SSL()
{
	SSL_METHOD* meth;
	SSL_CTX* ctx;
	int err;
	SSL* ssl;

	// Step 0: OpenSSL library initialization 
	// This step is no longer needed as of version 1.1.0.
	SSL_library_init();
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();

	// Step 1: SSL context initialization
	meth = SSLv23_server_method();
	ctx = SSL_CTX_new(meth);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	// SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_load_verify_locations(ctx, CACERT, NULL);

	// Step 2: Set up the server certificate and private key
	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(3);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(4);
	}
	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr, "Private key does not match the certificate public key\n");
		exit(5);
	}
	// Step 3: Create a new SSL structure for a connection
	// TODO 简化
	ssl = SSL_new(ctx);
	return ssl;
}

int init_TCP()
{
	struct sockaddr_in sockaddr_server;
	int server_sock;

	server_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	CHK_ERR(server_sock, "socket");
	memset(&sockaddr_server, '\0', sizeof(sockaddr_server));
	sockaddr_server.sin_family = AF_INET;
	sockaddr_server.sin_addr.s_addr = INADDR_ANY;
	sockaddr_server.sin_port = htons(4433);
	int err = bind(server_sock, (struct sockaddr*)&sockaddr_server, sizeof(sockaddr_server));

	CHK_ERR(err, "bind");
	err = listen(server_sock, 5);
	CHK_ERR(err, "listen");
	return server_sock;
}

int init_TUN()
{
	int tunfd;
	struct ifreq ifr;
	int ret;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	tunfd = open("/dev/net/tun", O_RDWR);
	if (tunfd == -1) {
		printf("Open /dev/net/tun failed! (%d: %s)\n", errno, strerror(errno));
		return -1;
	}
	ret = ioctl(tunfd, TUNSETIFF, &ifr);
	if (ret == -1) {
		printf("Setup TUN interface by ioctl failed! (%d: %s)\n", errno, strerror(errno));
		return -1;
	}

	printf("Setup TUN interface success!\n");
	return tunfd;
}

int auth(SSL* ssl)
{
	struct spwd* pw;
	char user[1024], passwd[1024];
	memset(&name, 0, sizeof(name));
	memset(&password, 0, sizeof(password));

	// SSL接收用户名和密码
	user[SSL_read(ssl, user, sizeof(user) - 1)] = '\0';
	passwd[SSL_read(ssl, passwd, sizeof(passwd) - 1)] = '\0';
	char* encrypted;
	char auth_result[2][] = {
		"failed",
		"ok",
	}

	// 获取/etc/shadow相应记录
	pw = getspnam(user);
	if (pw == NULL) {
		printf("Password is NULL.");
		return -1;
	}
	printf("[Auth] username: %s\n", pw->sp_namp);
	printf("[Auth] password: %s\n", pw->sp_pwdp);

	// 对比加密数据
	encrypted = crypt(passwd, pw->sp_pwdp);
	if (strcmp(encrypted, pw->sp_pwdp)) {
		printf("[Auth] password unmatched\n");
		SSL_write(ssl, auth_result[0], strlen(auth_result[0]));
		return 0;
	}
	SSL_write(ssl, auth_result[1], strlen(auth_result[1]));
	return 1;
}

void* listen_tun(void* tun_data)
{
	TunData* tun_data_ptr = (TunData*)tun_data;
	char buf[2024];
	memset(buf, 0, 2024);
	while (1) {
		int len = read(tun_data_ptr->tunfd, buf, 2024);
		if (len > 19 && buf[0] == 0x45) {
			tun_data_ptr->info->id = (int)buf[19];
			sprintf(tun_data_ptr->info->pipe_path, "./pipe/%d", tun_data_ptr->info->id);
			printf("[TUN] IP.des = 192.168.53.%d, size = %d\n", tun_data_ptr->info->id, len);

			int pipe_fd = open(tun_data_ptr->info->pipe_path, O_WRONLY);
			if (pipe_fd == -1) {
				printf("[BUG] can't open pipe_file\n");
				exit(-5);
			} else {
				write(pipe_fd, buf, len);
			}
		}
	}
}

void* listen_pipe(void* pipe_data)
{

}

void select_tun(int tunfd, struct sockaddr_in sockaddr_client, SSL* ssl)
{
	int len;
	char buf[2024];

	printf("Got a packet from TUN,ip:%s,port:%d\n", inet_ntoa(sockaddr_client.sin_addr), ntohs(sockaddr_client.sin_port));

	memset(buf, 0, 2024);
	len = read(tunfd, buf, 2024);
	SSL_write(ssl, buf, len);
}

void select_sock(int tunfd, struct sockaddr_in sockaddr_client, SSL* ssl)
{
	int len;
	char buf[2024];
	printf("[VPN] Got a packet from the tunnel,ip:%s,port:%d\n", inet_ntoa(sockaddr_client.sin_addr), ntohs(sockaddr_client.sin_port));
	memset(buf, 0, 2024);
	len = SSL_read(ssl, buf, 2024);
	if (len == 0)
		return -1;
	write(tunfd, buf, len);
	return 1;
}

void processRequest(SSL* ssl, int sock)
{
	int flag = 0
		while (1) {
			fd_set readFDSet;

			// 接收数据

			// 发送数据(分路)
		}

	// Construct and send the HTML page
	char* html = "HTTP/1.1 200 OK\r\n" "Content-Type: text/html\r\n\r\n" "<!DOCTYPE html><html>" "<head><title>Hello World</title></head>" "<style>body {background-color: black}" "h1 {font-size:3cm; text-align: center; color: white;" "text-shadow: 0 0 3mm yellow}</style></head>" "<body><h1>Hello, world!</h1></body></html>";

	SSL_write(ssl, html, strlen(html));
	SSL_shutdown(ssl);
	SSL_free(ssl);

	// Enter the main loop
	int flag = 0;
	while (1) {
		fd_set readFDSet;

		FD_ZERO(&readFDSet);
		FD_SET(SSL_get_fd(ssl), &readFDSet);
		FD_SET(tunfd, &readFDSet);
		select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

		if (FD_ISSET(tunfd, &readFDSet))
			tunSelected(tunfd, sa_client, ssl);//tun接口收到数据，向外网转发
		if (FD_ISSET(SSL_get_fd(ssl), &readFDSet))
			flag = socketSelected(tunfd, sa_client, ssl);//收到数据，向内网转发
		if (flag == -1)
			break;
	}
	printf("(%s,%d) has left\n", inet_ntoa(sa_client.sin_addr), ntohs(sa_client.sin_port));
	SSL_shutdown(ssl);
	SSL_free(ssl);
}