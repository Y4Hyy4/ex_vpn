#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>

/* define HOME to be dir for key and cert files... */
#define HOME	"./cert_hwk/"

/* Make these what you want for cert & key files */
#define CERTF	HOME"client.crt"
#define KEYF	HOME"client.key"
#define CACERT	HOME"ca.crt"

#define CHK_NULL(x)	if ((x)==NULL) exit (1)
#define CHK_SSL(err)	if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }

int verify_callback(int preverify_ok, X509_STORE_CTX* x509_ctx)
SSL* init_SSL(const char* hostname);			// SSL初始化(SSL层)
int init_TCP(const char* hostname, int port);	// TCP初始化(socket接口)
int init_TUN();									// Tun初始化(tun0接口)
void login(SSL* ssl);							// 客户端登录
void select_tun(int tunfd, int sockfd, SSL* ssl)// 发送数据 
int select_sock(int tunfd, int sockfd, SSL* ssl)// 接收数据


int main(int argc, char* argv[])
{
	// 接收cmd参数
	char* hostname = "10.0.2.8";
	int port = 4443;

	if (argc > 1)
		hostname = argv[1];
	if (argc > 2)
		port = atoi(argv[2]);

	// 初始化
	SSL* ssl = init_SSL(hostname);
	int sockfd = init_TCP(hostname, port);
	int tunfd = init_TUN();

	SSL_set_fd(ssl, sockfd);
	CHK_NULL(ssl);
	int err = SSL_connect(ssl);

	CHK_SSL(err);
	printf("[SSL] connection established\n");
	// printf("[SLL] connection using %s\n", SSL_get_cipher(ssl));

	login(ssl);

	char buf[2024];
	char cmd[200];
	memset(buf, 0, sizeof(buf));
	memset(cmd, 0, sizeof(cmd));

	sprintf(cmd, "ifconfig tun0 192.168.53.%d/24 up", atoi(buf));
	system(cmd);
	system("route add -net 192.168.60.0/24 tun0");
	buf[SSL_read(ssl, buf, BUFF_SIZE)] = '\0';

	int flag = 0;
	while (1) {
		fd_set readFDSet;
		FD_ZERO(&readFDSet);
		FD_SET(sockfd, &readFDSet);
		FD_SET(tunfd, &readFDSet);
		select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
		if (FD_ISSET(tunfd, &readFDSet))
			select_tun(tunfd, sockfd, ssl);
		if (FD_ISSET(sockfd, &readFDSet))
			flag = select_sock(tunfd, sockfd, ssl);
		if (!flag)
			break;
	}
}

int verify_callback(int preverify_ok, X509_STORE_CTX* x509_ctx)
{
	char buf[300];

	X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);

	X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
	printf("subject= %s\n", buf);

	if (preverify_ok == 1) {
		printf("Verification passed.\n");
	} else {
		int err = X509_STORE_CTX_get_error(x509_ctx);
		printf("Verification failed: %s.\n", X509_verify_cert_error_string(err));
	}
}

SSL* init_SSL(const char* hostname)
{
	// Step 0: OpenSSL library initialization 
	// This step is no longer needed as of version 1.1.0.
	SSL_library_init();
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();

	SSL_METHOD* meth;
	SSL_CTX* ctx;
	SSL* ssl;

	meth = SSLv23_client_method();
	ctx = SSL_CTX_new(meth);

	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, verify_callback);
	SSL_CTX_load_verify_locations(ctx, CACERT, NULL);

	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(-2);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(-3);
	}
	if (!SSL_CTX_check_private_key(ctx)) {
		printf("Private key does not match the certificate public keyn");
		exit(-4);
	}
	ssl = SSL_new(ctx);

	X509_VERIFY_PARAM* vpm = SSL_get0_param(ssl);
	X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

	return ssl;
}

int init_TCP(const char* hostname, int port)
{
	struct sockaddr_in server_addr;

	// Get the IP address from hostname
	struct hostent* hp = gethostbyname(hostname);

	// Create a TCP socket
	int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	// Fill in the destination information (IP, port #, and family)
	memset(&server_addr, '\0', sizeof(server_addr));
	memcpy(&(server_addr.sin_addr.s_addr), hp->h_addr, hp->h_length);
	//server_addr.sin_addr.s_addr = inet_addr ("10.0.2.14"); 
	server_addr.sin_port = htons(port);
	server_addr.sin_family = AF_INET;

	// Connect to the destination
	connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr));

	return sockfd;
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

void login(SSL* ssl)
{
	char user[1024], passwd[1024];
	char res_login[1024];
	memset(user, 0, 1024);
	memset(passwd, 0, 1024);
	memset(res_login, 0, 1024);

	printf("[Login] username:\n");
	scanf("%s", user);
	getchar();
	memcpy(passwd, getpass("[Login] password:\n "), 1024);

	SSL_write(ssl, user, strlen(user));
	SSL_write(ssl, passwd, strlen(passwd));

	res_login[SSL_read(ssl, res_login, strlen(res_login))] = '\0';
	if (strcmp(res_login, "failed") == 0) {
		printf("[Login] fail\n");
		SSL_shutdown(ssl);
		SSL_free(ssl);
		exit(2);
	} else if (strcmp(res_login, "ok") == 0) {
		printf("[Login] success\n");
		return;
	} else {
		printf("[Login] bug!!!\n");
		exit(2);
	}
}

void select_tun(int tunfd, int sockfd, SSL* ssl)
{
	int len;
	char buf[2024];
	printf("[TUN] Got a packet from TUN\n");

	memset(buf, 0, 2024);
	len = read(tunfd, buf, BUFF_SIZE);
	SSL_write(ssl, buf, len);
}

int select_sock(int tunfd, int sockfd, SSL* ssl)
{
	int len;
	char buf[2024];
	printf("[VPN] Got a packet from the tunnel\n");

	memset(buf, 0, 2024);
	len = SSL_read(ssl, buf, BUFF_SIZE);
	if (len == 0) {
		printf("[VPN] STOP\n");
		return 0;
	}
	write(tunfd, buf, len);
	return 1;
}