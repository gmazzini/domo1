// Gianluca Mazzini @2011- Version 5.02

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#define PROGRAM_VERSION "5.02"
#define CONFIG_FILE "config"
#define DEFAULT_LOG_FILE "domotic.log"
#define LISTEN_IP "10.0.0.8"
#define LISTEN_PORT 3333
#define BOARD_COUNT 4
#define INPUT_DEVICE_COUNT 6
#define TOTAL_RELAYS 64
#define TOTAL_KEYS 72
#define PHYSICAL_KEYS 64
#define MAX_RULES 128
#define MAX_RULE_VALUES 96
#define MAX_RULE_NAME 64
#define MAX_CONFIG_VERSION 16
#define MAX_LOG_PATH 256
#define MAX_EVENTS 256
#define CONFIG_LINE_SIZE 2048
#define HTTP_REQUEST_SIZE 2048
#define HTTP_BODY_SIZE 65536
#define FORMAT_BUFFER_SIZE 2048
#define LOG_LINE_SIZE 512
#define CONNECT_TIMEOUT_MS 500
#define SOCKET_TIMEOUT_MS 300
#define SCAN_DELAY_NS 20000000L
#define LEVEL_INTERVAL_CS 500UL

#define RULE_3LEVEL 0
#define RULE_ONOFF 1
#define RULE_ON 2
#define RULE_OFF 3
#define RULE_ALLOFF 4
#define RULE_INJECT_IF_OFF 6
#define RULE_INJECT_IF_ON 7
#define RULE_PUSH 8
#define RULE_OFF_TIMED 9
#define RULE_OFF_TIMED_KEYSUP 10
#define RULE_3LIGHT 11

typedef struct {
  int type;
  int count;
  unsigned short value[MAX_RULE_VALUES];
  char name[MAX_RULE_NAME];
} Rule;

typedef struct {
  char version[MAX_CONFIG_VERSION];
  char log_path[MAX_LOG_PATH];
  int rule_count;
  Rule rule[MAX_RULES];
} Config;

typedef struct {
  unsigned char key;
  unsigned char state;
  unsigned long time_cs;
} KeyEvent;

typedef struct {
  char data[HTTP_BODY_SIZE];
  unsigned long len;
} Text;

static const char *board_ip[BOARD_COUNT]={
  "10.0.0.21", "10.0.0.22", "10.0.0.23", "10.0.0.24"
};

static const char *bem_input_ip[2]={"10.0.0.33", "10.0.0.35"};
static const char *bem_output_ip[2]={"10.0.0.32", "10.0.0.34"};
static const int key_base[7]={0,12,24,36,48,56,64};

static Config config_data;
static KeyEvent event_list[MAX_EVENTS];
static unsigned char inject_release[MAX_EVENTS];
static unsigned char relay_state[TOTAL_RELAYS];
static unsigned char relay_old[TOTAL_RELAYS];
static unsigned char key_down[TOTAL_KEYS];
static unsigned char input_valid[INPUT_DEVICE_COUNT];
static unsigned short input_state[INPUT_DEVICE_COUNT];
static unsigned short input_old[INPUT_DEVICE_COUNT];
static unsigned long relay_time[TOTAL_RELAYS];
static unsigned long key_last_release[TOTAL_KEYS];
static int input_fd[INPUT_DEVICE_COUNT];
static int event_count;
static int inject_count;
static int keyoff;
static int server_fd;
static FILE *log_fp;
static volatile sig_atomic_t running=1;
static Text http_body;

static void stop_program(int sig);
static unsigned long monotonic_cs(void);
static void scan_delay(void);
static void wall_time_string(char *out, int size);
static void log_message(const char *format, ...);
static void text_clear(Text *text);
static void text_add(Text *text, const char *value);
static void text_addn(Text *text, const char *value, unsigned long size);
static void text_addf(Text *text, const char *format, ...);
static int parse_number(const char *text, long min, long max, long *value);
static char *trim(char *text);
static int validate_rule(Rule *rule, char *error, int error_size);
static int load_config(const char *path, Config *out, char *error, int error_size);
static const char *rule_type_name(int type);
static int open_log(const char *path, FILE **out);
static int connect_tcp(const char *ip, int port);
static int open_server(void);
static void close_input(int dev);
static int ensure_input(int dev);
static int send_all(int fd, const void *buffer, int size);
static int recv_exact(int fd, void *buffer, int size);
static int send_board_command(int dev, unsigned char command, unsigned char value);
static int read_bem_input(int dev, unsigned short *value);
static void initialize_hardware(void);
static void read_inputs(void);
static void add_event(int key, int state, unsigned long now);
static void scan_keys(unsigned long now);
static void release_injected(unsigned long now);
static void inject_key(int key, unsigned long now);
static int hour_active(int hour, int start, int end);
static void set_relay(int relay, int value, unsigned long now);
static void process_timed_rules(int hour, int minute, unsigned long now);
static void process_actions(int hour, unsigned long now);
static void update_key_times(void);
static int send_bem_outputs(int first_relay, const char *ip);
static void write_outputs(void);
static int rule_has_key(const Rule *rule, int key);
static int rule_has_relay(const Rule *rule, int relay);
static void show_rule(Text *text, int index, const Rule *rule);
static void append_log_reverse(Text *text, int lines);
static int reload_config(Text *text);
static void command_status(Text *text);
static void command_keystatus(Text *text);
static void command_rules(Text *text);
static void command_keys(Text *text);
static void command_relays(Text *text);
static void command_help(Text *text);
static void handle_command(Text *text, char *path, const char *request_line);
static void handle_client(int fd);
static void service_http(void);
static void cleanup(void);

static void stop_program(int sig) {
  if(sig==SIGINT||sig==SIGTERM) running=0;
}

static unsigned long monotonic_cs(void) {
  static int initialized=0;
  static struct timespec origin;
  struct timespec now;
  time_t sec;
  long nsec;

  if(!initialized) {
    if(clock_gettime(CLOCK_MONOTONIC,&origin)!=0) return 0;
    initialized=1;
  }
  if(clock_gettime(CLOCK_MONOTONIC,&now)!=0) return 0;
  sec=now.tv_sec-origin.tv_sec;
  nsec=now.tv_nsec-origin.tv_nsec;
  if(nsec<0) {
    sec--;
    nsec+=1000000000L;
  }
  return (unsigned long)sec*100UL+(unsigned long)(nsec/10000000L);
}

static void scan_delay(void) {
  struct timespec delay;

  delay.tv_sec=0;
  delay.tv_nsec=SCAN_DELAY_NS;
  for(;nanosleep(&delay,&delay)!=0&&errno==EINTR;);
}

static void wall_time_string(char *out, int size) {
  struct timespec now;
  struct tm *local;
  int cs;

  if(size<24) {
    if(size>0) out[0]='\0';
    return;
  }
  if(clock_gettime(CLOCK_REALTIME,&now)!=0) {
    strcpy(out,"00-00-0000/00:00:00.00");
    return;
  }
  local=localtime(&now.tv_sec);
  if(local==NULL) {
    strcpy(out,"00-00-0000/00:00:00.00");
    return;
  }
  cs=(int)(now.tv_nsec/10000000L);
  sprintf(out,"%02d-%02d-%04d/%02d:%02d:%02d.%02d",
    local->tm_mday,local->tm_mon+1,local->tm_year+1900,
    local->tm_hour,local->tm_min,local->tm_sec,cs);
}

static void log_message(const char *format, ...) {
  va_list args;

  if(log_fp==NULL) return;
  va_start(args,format);
  vfprintf(log_fp,format,args);
  va_end(args);
  fflush(log_fp);
}

static void text_clear(Text *text) {
  text->len=0;
  text->data[0]='\0';
}

static void text_addn(Text *text, const char *value, unsigned long size) {
  unsigned long free_size;

  if(text->len>=HTTP_BODY_SIZE-1) return;
  free_size=(HTTP_BODY_SIZE-1)-text->len;
  if(size>free_size) size=free_size;
  if(size) {
    memcpy(text->data+text->len,value,(size_t)size);
    text->len+=size;
    text->data[text->len]='\0';
  }
}

static void text_add(Text *text, const char *value) {
  text_addn(text,value,(unsigned long)strlen(value));
}

static void text_addf(Text *text, const char *format, ...) {
  char buffer[FORMAT_BUFFER_SIZE];
  va_list args;

  va_start(args,format);
  vsprintf(buffer,format,args);
  va_end(args);
  text_add(text,buffer);
}

static int parse_number(const char *text, long min, long max, long *value) {
  char *end;
  long parsed;

  if(text==NULL||*text=='\0') return -1;
  errno=0;
  parsed=strtol(text,&end,10);
  if(errno!=0||*end!='\0'||parsed<min||parsed>max) return -1;
  *value=parsed;
  return 0;
}

static char *trim(char *text) {
  char *end;

  for(;*text==' '||*text=='\t'||*text=='\r'||*text=='\n';text++);
  end=text+strlen(text);
  for(;end>text;) {
    if(end[-1]!=' '&&end[-1]!='\t'&&end[-1]!='\r'&&end[-1]!='\n') break;
    end--;
  }
  *end='\0';
  return text;
}

static int validate_rule(Rule *rule, char *error, int error_size) {
  int i;
  int n;
  int m;
  int q;
  int v;
  int expected;

  if(rule->name[0]=='\0') {
    sprintf(error,"rule name is empty");
    return -1;
  }
  if(rule->count<2||rule->value[0]>23||rule->value[1]>23) {
    sprintf(error,"invalid hour range in rule %s",rule->name);
    return -1;
  }
  if(rule->type==RULE_INJECT_IF_OFF||rule->type==RULE_INJECT_IF_ON) {
    if(rule->count!=4||rule->value[1]>59||rule->value[2]>=TOTAL_KEYS||
      rule->value[3]>=TOTAL_RELAYS) {
      sprintf(error,"invalid timed injection rule %s",rule->name);
      return -1;
    }
    return 0;
  }
  if(rule->type==RULE_OFF_TIMED) {
    if(rule->count!=4||rule->value[2]>=TOTAL_RELAYS) {
      sprintf(error,"invalid offtimed rule %s",rule->name);
      return -1;
    }
    return 0;
  }
  if(rule->type==RULE_OFF_TIMED_KEYSUP) {
    if(rule->count<5) {
      sprintf(error,"invalid offtimed_keysup rule %s",rule->name);
      return -1;
    }
    n=rule->value[2];
    expected=5+n;
    if(n<1||rule->count!=expected) {
      sprintf(error,"invalid key count in rule %s",rule->name);
      return -1;
    }
    for(i=0;i<n;i++) {
      if(rule->value[3+i]>=TOTAL_KEYS) {
        sprintf(error,"invalid key in rule %s",rule->name);
        return -1;
      }
    }
    if(rule->value[3+n]>=TOTAL_RELAYS) {
      sprintf(error,"invalid relay in rule %s",rule->name);
      return -1;
    }
    return 0;
  }
  if(rule->type==RULE_3LEVEL) {
    if(rule->count<5) {
      sprintf(error,"invalid 3level rule %s",rule->name);
      return -1;
    }
    n=rule->value[2];
    if(3+n>=rule->count) {
      sprintf(error,"invalid key count in rule %s",rule->name);
      return -1;
    }
    m=rule->value[3+n];
    if(4+n+m>=rule->count) {
      sprintf(error,"invalid relay A count in rule %s",rule->name);
      return -1;
    }
    q=rule->value[4+n+m];
    expected=5+n+m+q;
    if(rule->count!=expected) {
      sprintf(error,"invalid 3level size in rule %s",rule->name);
      return -1;
    }
  } else if(rule->type==RULE_3LIGHT) {
    if(rule->count<6) {
      sprintf(error,"invalid 3light rule %s",rule->name);
      return -1;
    }
    n=rule->value[2];
    if(3+n>=rule->count) {
      sprintf(error,"invalid key count in rule %s",rule->name);
      return -1;
    }
    m=rule->value[3+n];
    if(4+n+m>=rule->count) {
      sprintf(error,"invalid relay A count in rule %s",rule->name);
      return -1;
    }
    q=rule->value[4+n+m];
    if(5+n+m+q>=rule->count) {
      sprintf(error,"invalid relay B count in rule %s",rule->name);
      return -1;
    }
    v=rule->value[5+n+m+q];
    expected=6+n+m+q+v;
    if(rule->count!=expected) {
      sprintf(error,"invalid 3light size in rule %s",rule->name);
      return -1;
    }
  } else if(rule->type==RULE_ONOFF||rule->type==RULE_ON||
    rule->type==RULE_OFF||rule->type==RULE_ALLOFF||rule->type==RULE_PUSH) {
    if(rule->count<4) {
      sprintf(error,"invalid rule %s",rule->name);
      return -1;
    }
    n=rule->value[2];
    if(3+n>=rule->count) {
      sprintf(error,"invalid key count in rule %s",rule->name);
      return -1;
    }
    m=rule->value[3+n];
    expected=4+n+m;
    if(rule->count!=expected) {
      sprintf(error,"invalid relay count in rule %s",rule->name);
      return -1;
    }
    q=0;
    v=0;
  } else {
    sprintf(error,"unsupported rule type %d",rule->type);
    return -1;
  }

  n=rule->value[2];
  for(i=0;i<n;i++) {
    if(rule->value[3+i]>=TOTAL_KEYS) {
      sprintf(error,"invalid key in rule %s",rule->name);
      return -1;
    }
  }
  if(rule->type==RULE_3LEVEL||rule->type==RULE_3LIGHT) {
    m=rule->value[3+n];
    for(i=0;i<m;i++) {
      if(rule->value[4+n+i]>=TOTAL_RELAYS) {
        sprintf(error,"invalid relay A in rule %s",rule->name);
        return -1;
      }
    }
    q=rule->value[4+n+m];
    for(i=0;i<q;i++) {
      if(rule->value[5+n+m+i]>=TOTAL_RELAYS) {
        sprintf(error,"invalid relay B in rule %s",rule->name);
        return -1;
      }
    }
    if(rule->type==RULE_3LIGHT) {
      v=rule->value[5+n+m+q];
      for(i=0;i<v;i++) {
        if(rule->value[6+n+m+q+i]>=TOTAL_RELAYS) {
          sprintf(error,"invalid relay C in rule %s",rule->name);
          return -1;
        }
      }
    }
  } else {
    m=rule->value[3+n];
    for(i=0;i<m;i++) {
      if(rule->value[4+n+i]>=TOTAL_RELAYS) {
        sprintf(error,"invalid relay in rule %s",rule->name);
        return -1;
      }
    }
  }
  if(error_size>0) error[error_size-1]='\0';
  return 0;
}

static int load_config(const char *path, Config *out, char *error, int error_size) {
  FILE *fp;
  Config temp;
  Rule *rule;
  char line[CONFIG_LINE_SIZE];
  char work[CONFIG_LINE_SIZE];
  char *text;
  char *name;
  char *token;
  char *separator;
  long number;
  int line_number;
  int i;
  int have_version;

  memset(&temp,0,sizeof(temp));
  strcpy(temp.log_path,DEFAULT_LOG_FILE);
  fp=fopen(path,"r");
  if(fp==NULL) {
    sprintf(error,"cannot open %s: %s",path,strerror(errno));
    return -1;
  }
  line_number=0;
  have_version=0;
  for(;fgets(line,sizeof(line),fp)!=NULL;) {
    line_number++;
    text=trim(line);
    if(*text=='\0'||*text=='#') continue;
    if(strncmp(text,"version ",8)==0) {
      text=trim(text+8);
      if(*text=='\0'||strlen(text)>=sizeof(temp.version)) {
        sprintf(error,"line %d: invalid version",line_number);
        fclose(fp);
        return -1;
      }
      strcpy(temp.version,text);
      have_version=1;
      continue;
    }
    if(strncmp(text,"log ",4)==0) {
      text=trim(text+4);
      if(*text=='\0'||strlen(text)>=sizeof(temp.log_path)) {
        sprintf(error,"line %d: invalid log path",line_number);
        fclose(fp);
        return -1;
      }
      strcpy(temp.log_path,text);
      continue;
    }
    if(strncmp(text,"rule ",5)!=0) {
      sprintf(error,"line %d: unknown directive",line_number);
      fclose(fp);
      return -1;
    }
    if(temp.rule_count>=MAX_RULES) {
      sprintf(error,"line %d: too many rules",line_number);
      fclose(fp);
      return -1;
    }
    if(strlen(text)>=sizeof(work)) {
      sprintf(error,"line %d: rule too long",line_number);
      fclose(fp);
      return -1;
    }
    strcpy(work,text+5);
    separator=strchr(work,'|');
    if(separator==NULL) {
      sprintf(error,"line %d: missing rule name separator",line_number);
      fclose(fp);
      return -1;
    }
    *separator='\0';
    name=trim(separator+1);
    if(*name=='\0'||strlen(name)>=MAX_RULE_NAME) {
      sprintf(error,"line %d: invalid rule name",line_number);
      fclose(fp);
      return -1;
    }
    rule=&temp.rule[temp.rule_count];
    memset(rule,0,sizeof(*rule));
    strcpy(rule->name,name);
    token=strtok(work," \t");
    if(token==NULL||parse_number(token,0,11,&number)!=0) {
      sprintf(error,"line %d: invalid rule type",line_number);
      fclose(fp);
      return -1;
    }
    rule->type=(int)number;
    i=0;
    for(token=strtok(NULL," \t");token!=NULL;token=strtok(NULL," \t")) {
      if(i>=MAX_RULE_VALUES||parse_number(token,0,65535,&number)!=0) {
        sprintf(error,"line %d: invalid rule value",line_number);
        fclose(fp);
        return -1;
      }
      rule->value[i]=(unsigned short)number;
      i++;
    }
    rule->count=i;
    if(validate_rule(rule,error,error_size)!=0) {
      char detail[CONFIG_LINE_SIZE];

      strcpy(detail,error);
      sprintf(error,"line %d: %s",line_number,detail);
      fclose(fp);
      return -1;
    }
    temp.rule_count++;
  }
  if(ferror(fp)) {
    sprintf(error,"cannot read %s: %s",path,strerror(errno));
    fclose(fp);
    return -1;
  }
  fclose(fp);
  if(!have_version) {
    sprintf(error,"missing version directive");
    return -1;
  }
  *out=temp;
  if(error_size>0) error[0]='\0';
  return 0;
}

static const char *rule_type_name(int type) {
  switch(type) {
    case RULE_3LEVEL: return "3level";
    case RULE_ONOFF: return "onoff";
    case RULE_ON: return "on";
    case RULE_OFF: return "off";
    case RULE_ALLOFF: return "alloff";
    case RULE_INJECT_IF_OFF: return "injectifoff";
    case RULE_INJECT_IF_ON: return "injectifon";
    case RULE_PUSH: return "push";
    case RULE_OFF_TIMED: return "offtimed";
    case RULE_OFF_TIMED_KEYSUP: return "offtimed_keysup";
    case RULE_3LIGHT: return "3light";
    case -1: return "deleted";
  }
  return "unknown";
}

static int open_log(const char *path, FILE **out) {
  FILE *fp;

  fp=fopen(path,"a+");
  if(fp==NULL) return -1;
  setvbuf(fp,NULL,_IOLBF,0);
  *out=fp;
  return 0;
}

static int connect_tcp(const char *ip, int port) {
  struct sockaddr_in address;
  struct timeval timeout;
  fd_set write_set;
  socklen_t length;
  int fd;
  int flags;
  int error;
  int one;
  int result;

  fd=socket(AF_INET,SOCK_STREAM,0);
  if(fd<0) return -1;
  one=1;
  setsockopt(fd,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one));
  flags=fcntl(fd,F_GETFL,0);
  if(flags<0||fcntl(fd,F_SETFL,flags|O_NONBLOCK)<0) {
    close(fd);
    return -1;
  }
  memset(&address,0,sizeof(address));
  address.sin_family=AF_INET;
  address.sin_port=htons((unsigned short)port);
  address.sin_addr.s_addr=inet_addr(ip);
  result=connect(fd,(struct sockaddr *)&address,sizeof(address));
  if(result<0&&errno!=EINPROGRESS) {
    close(fd);
    return -1;
  }
  if(result<0) {
    FD_ZERO(&write_set);
    FD_SET(fd,&write_set);
    timeout.tv_sec=CONNECT_TIMEOUT_MS/1000;
    timeout.tv_usec=(CONNECT_TIMEOUT_MS%1000)*1000;
    result=select(fd+1,NULL,&write_set,NULL,&timeout);
    if(result<=0) {
      close(fd);
      return -1;
    }
    error=0;
    length=sizeof(error);
    if(getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&length)<0||error!=0) {
      close(fd);
      return -1;
    }
  }
  if(fcntl(fd,F_SETFL,flags)<0) {
    close(fd);
    return -1;
  }
  timeout.tv_sec=SOCKET_TIMEOUT_MS/1000;
  timeout.tv_usec=(SOCKET_TIMEOUT_MS%1000)*1000;
  setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
  setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
  return fd;
}

static int open_server(void) {
  struct sockaddr_in address;
  int fd;
  int flags;
  int one;

  fd=socket(AF_INET,SOCK_STREAM,0);
  if(fd<0) return -1;
  one=1;
  setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
  memset(&address,0,sizeof(address));
  address.sin_family=AF_INET;
  address.sin_port=htons(LISTEN_PORT);
  address.sin_addr.s_addr=inet_addr(LISTEN_IP);
  if(bind(fd,(struct sockaddr *)&address,sizeof(address))<0||listen(fd,16)<0) {
    close(fd);
    return -1;
  }
  flags=fcntl(fd,F_GETFL,0);
  if(flags<0||fcntl(fd,F_SETFL,flags|O_NONBLOCK)<0) {
    close(fd);
    return -1;
  }
  return fd;
}

static void close_input(int dev) {
  if(dev<0||dev>=INPUT_DEVICE_COUNT) return;
  if(input_fd[dev]>=0) close(input_fd[dev]);
  input_fd[dev]=-1;
}

static int ensure_input(int dev) {
  const char *ip;
  int port;

  if(dev<0||dev>=INPUT_DEVICE_COUNT) return -1;
  if(input_fd[dev]>=0) return input_fd[dev];
  if(dev<BOARD_COUNT) {
    ip=board_ip[dev];
    port=10001;
  } else {
    ip=bem_input_ip[dev-BOARD_COUNT];
    port=5000;
  }
  input_fd[dev]=connect_tcp(ip,port);
  return input_fd[dev];
}

static int send_all(int fd, const void *buffer, int size) {
  const char *ptr;
  ssize_t sent;
  int done;

  ptr=(const char *)buffer;
  done=0;
  for(;done<size;) {
    sent=send(fd,ptr+done,(size_t)(size-done),MSG_NOSIGNAL);
    if(sent<0&&errno==EINTR) continue;
    if(sent<=0) return -1;
    done+=(int)sent;
  }
  return 0;
}

static int recv_exact(int fd, void *buffer, int size) {
  char *ptr;
  ssize_t received;
  int done;

  ptr=(char *)buffer;
  done=0;
  for(;done<size;) {
    received=recv(fd,ptr+done,(size_t)(size-done),0);
    if(received<0&&errno==EINTR) continue;
    if(received<=0) return -1;
    done+=(int)received;
  }
  return 0;
}

static int send_board_command(int dev, unsigned char command, unsigned char value) {
  unsigned char message[2];
  int fd;

  fd=ensure_input(dev);
  if(fd<0) return -1;
  message[0]=command;
  message[1]=value;
  if(send_all(fd,message,2)!=0) {
    close_input(dev);
    return -1;
  }
  return 0;
}

static int read_bem_input(int dev, unsigned short *value) {
  static const char *request[2]={
    "getpara[189]=1;getpara[190]=1;getpara[191]=1;getpara[192]=1;getpara[193]=1;getpara[194]=1;getpara[195]=1;getpara[196]=1;",
    "getpara[196]=1;getpara[195]=1;getpara[194]=1;getpara[193]=1;getpara[192]=1;getpara[191]=1;getpara[190]=1;getpara[189]=1;"
  };
  char response[1024];
  char *ptr;
  ssize_t received;
  int fd;
  int used;
  int semicolons;
  int i;
  int bit_count;
  unsigned short result;

  fd=ensure_input(dev);
  if(fd<0) return -1;
  if(send_all(fd,request[dev-BOARD_COUNT],(int)strlen(request[dev-BOARD_COUNT]))!=0) {
    close_input(dev);
    return -1;
  }
  used=0;
  semicolons=0;
  for(;used<(int)sizeof(response)-1&&semicolons<8;) {
    received=recv(fd,response+used,sizeof(response)-1-(size_t)used,0);
    if(received<0&&errno==EINTR) continue;
    if(received<=0) {
      close_input(dev);
      return -1;
    }
    for(i=0;i<(int)received;i++) if(response[used+i]==';') semicolons++;
    used+=(int)received;
  }
  response[used]='\0';
  result=0;
  bit_count=0;
  ptr=response;
  for(;*ptr!='\0'&&bit_count<8;ptr++) {
    if(*ptr!='=') continue;
    ptr++;
    for(;*ptr!='\0'&&*ptr!='0'&&*ptr!='1';ptr++);
    if(*ptr=='\0') break;
    result=(unsigned short)((result<<1)+(1-(*ptr-'0')));
    bit_count++;
  }
  if(bit_count!=8) {
    close_input(dev);
    return -1;
  }
  *value=result;
  return 0;
}

static void initialize_hardware(void) {
  char message[16];
  int fd;
  int dev;
  int i;

  for(dev=0;dev<BOARD_COUNT;dev++) send_board_command(dev,0x42,0x00);
  scan_delay();
  for(dev=0;dev<BOARD_COUNT;dev++) send_board_command(dev,0x45,0x0f);
  scan_delay();
  for(dev=0;dev<BOARD_COUNT;dev++) send_board_command(dev,0x48,0xff);
  scan_delay();

  for(dev=0;dev<2;dev++) {
    fd=connect_tcp(bem_output_ip[dev],5000);
    if(fd<0) continue;
    for(i=0;i<8;i++) {
      sprintf(message,"k0%c=0;",'1'+i);
      if(send_all(fd,message,(int)strlen(message))!=0) break;
      scan_delay();
    }
    close(fd);
  }

  for(dev=0;dev<BOARD_COUNT;dev++) send_board_command(dev,0x43,0x00);
  scan_delay();
  for(dev=0;dev<BOARD_COUNT;dev++) send_board_command(dev,0x46,0x00);
  scan_delay();
  for(dev=0;dev<BOARD_COUNT;dev++) send_board_command(dev,0x4a,0x00);
  scan_delay();
}

static void read_inputs(void) {
  unsigned char low[BOARD_COUNT];
  unsigned char high[BOARD_COUNT];
  unsigned char low_ok[BOARD_COUNT];
  unsigned short value;
  int dev;

  memset(low_ok,0,sizeof(low_ok));
  memset(input_valid,0,sizeof(input_valid));
  for(dev=0;dev<BOARD_COUNT;dev++) {
    if(send_board_command(dev,0x47,0x00)==0) low_ok[dev]=1;
  }
  scan_delay();
  for(dev=0;dev<BOARD_COUNT;dev++) {
    if(!low_ok[dev]) continue;
    if(recv_exact(input_fd[dev],&low[dev],1)!=0) {
      low_ok[dev]=0;
      close_input(dev);
    }
  }
  for(dev=0;dev<BOARD_COUNT;dev++) {
    if(!low_ok[dev]) continue;
    if(send_board_command(dev,0x44,0x00)!=0) low_ok[dev]=0;
  }
  scan_delay();
  for(dev=0;dev<BOARD_COUNT;dev++) {
    if(!low_ok[dev]) continue;
    if(recv_exact(input_fd[dev],&high[dev],1)!=0) {
      close_input(dev);
      continue;
    }
    input_state[dev]=(unsigned short)(low[dev]|((high[dev]&0x0f)<<8));
    input_valid[dev]=1;
  }
  for(dev=BOARD_COUNT;dev<INPUT_DEVICE_COUNT;dev++) {
    if(read_bem_input(dev,&value)==0) {
      input_state[dev]=value;
      input_valid[dev]=1;
    }
  }
}

static void add_event(int key, int state, unsigned long now) {
  if(key<0||key>=TOTAL_KEYS||event_count>=MAX_EVENTS) return;
  event_list[event_count].key=(unsigned char)key;
  event_list[event_count].state=(unsigned char)(state?1:0);
  event_list[event_count].time_cs=now;
  event_count++;
}

static void scan_keys(unsigned long now) {
  unsigned short diff;
  unsigned short mask;
  int dev;
  int key;
  int count;
  int absolute;
  int state;

  if(keyoff) return;
  for(dev=0;dev<INPUT_DEVICE_COUNT;dev++) {
    if(!input_valid[dev]) continue;
    diff=(unsigned short)(input_state[dev]^input_old[dev]);
    count=key_base[dev+1]-key_base[dev];
    if(diff) {
      for(key=count-1;key>=0;key--) {
        mask=(unsigned short)(1U<<key);
        if(!(diff&mask)) continue;
        absolute=key_base[dev]+key;
        state=(input_state[dev]&mask)?0:1;
        key_down[absolute]=(unsigned char)state;
        add_event(absolute,state,now);
      }
    }
    input_old[dev]=input_state[dev];
    for(key=0;key<count;key++) {
      absolute=key_base[dev]+key;
      key_down[absolute]=(input_state[dev]&(1U<<key))?0:1;
    }
  }
}

static void release_injected(unsigned long now) {
  int i;
  int key;

  for(i=0;i<inject_count;i++) {
    key=inject_release[i];
    add_event(key,0,now);
    if(key>=PHYSICAL_KEYS) key_down[key]=0;
  }
  inject_count=0;
}

static void inject_key(int key, unsigned long now) {
  if(key<0||key>=TOTAL_KEYS||inject_count>=MAX_EVENTS) return;
  add_event(key,1,now);
  inject_release[inject_count]=(unsigned char)key;
  inject_count++;
  if(key>=PHYSICAL_KEYS) key_down[key]=1;
}

static int hour_active(int hour, int start, int end) {
  if(start<=end) return hour>=start&&hour<=end;
  return hour>=start||hour<=end;
}

static void set_relay(int relay, int value, unsigned long now) {
  if(relay<0||relay>=TOTAL_RELAYS) return;
  relay_state[relay]=(unsigned char)(value?1:0);
  relay_time[relay]=now;
}

static void process_timed_rules(int hour, int minute, unsigned long now) {
  Rule *rule;
  unsigned long elapsed;
  int n;
  int i;
  int key_count;
  int active;
  int relay;
  int minutes;

  for(n=0;n<config_data.rule_count;n++) {
    rule=&config_data.rule[n];
    if(rule->type<0) continue;
    if(rule->type==RULE_OFF_TIMED) {
      if(!hour_active(hour,rule->value[0],rule->value[1])) continue;
      relay=rule->value[2];
      if(!relay_state[relay]) continue;
      elapsed=now-relay_time[relay];
      minutes=rule->value[3];
      if(elapsed>(unsigned long)minutes*6000UL) set_relay(relay,0,now);
      continue;
    }
    if(rule->type==RULE_OFF_TIMED_KEYSUP) {
      if(!hour_active(hour,rule->value[0],rule->value[1])) continue;
      key_count=rule->value[2];
      relay=rule->value[3+key_count];
      if(!relay_state[relay]) continue;
      active=0;
      for(i=0;i<key_count;i++) if(key_down[rule->value[3+i]]) active=1;
      if(active) continue;
      minutes=rule->value[4+key_count];
      elapsed=now-relay_time[relay];
      if(elapsed>(unsigned long)minutes*6000UL) set_relay(relay,0,now);
      continue;
    }
    if(rule->type==RULE_INJECT_IF_OFF) {
      if(hour!=rule->value[0]||minute!=rule->value[1]) continue;
      if(!relay_state[rule->value[3]]) inject_key(rule->value[2],now);
      continue;
    }
    if(rule->type==RULE_INJECT_IF_ON) {
      if(hour!=rule->value[0]||minute!=rule->value[1]) continue;
      if(relay_state[rule->value[3]]) inject_key(rule->value[2],now);
    }
  }
}

static void process_actions(int hour, unsigned long now) {
  Rule *rule;
  KeyEvent *event;
  unsigned long duration;
  int n;
  int i;
  int j;
  int k;
  int key_count;
  int a_count;
  int b_count;
  int c_count;
  int a_on;
  int b_on;
  int c_on;
  int matched;
  int pressed;
  int relay;
  int skip;

  for(i=0;i<event_count;i++) {
    char stamp[32];

    wall_time_string(stamp,sizeof(stamp));
    log_message("key: %02d %01d %s\n",event_list[i].key,event_list[i].state,stamp);
  }

  for(n=0;n<config_data.rule_count;n++) {
    rule=&config_data.rule[n];
    if(rule->type<0) continue;
    if(rule->type==RULE_INJECT_IF_OFF||rule->type==RULE_INJECT_IF_ON||
      rule->type==RULE_OFF_TIMED||rule->type==RULE_OFF_TIMED_KEYSUP) continue;
    if(!hour_active(hour,rule->value[0],rule->value[1])) continue;
    key_count=rule->value[2];

    if(rule->type==RULE_PUSH) {
      matched=0;
      pressed=0;
      for(i=0;i<key_count;i++) {
        for(j=0;j<event_count;j++) {
          event=&event_list[j];
          if(rule->value[3+i]!=event->key) continue;
          matched++;
          if(event->state) pressed=1;
        }
      }
      if(matched) {
        a_count=rule->value[3+key_count];
        for(k=0;k<a_count;k++) set_relay(rule->value[4+key_count+k],pressed,now);
      }
      continue;
    }

    for(i=0;i<key_count;i++) {
      for(j=0;j<event_count;j++) {
        event=&event_list[j];
        if(rule->value[3+i]!=event->key||event->state) continue;

        if(rule->type==RULE_ONOFF||rule->type==RULE_ON||rule->type==RULE_OFF) {
          a_count=rule->value[3+key_count];
          a_on=0;
          for(k=0;k<a_count;k++) a_on+=relay_state[rule->value[4+key_count+k]];
          if(rule->type==RULE_ONOFF) {
            pressed=a_on==a_count?0:1;
            for(k=0;k<a_count;k++) set_relay(rule->value[4+key_count+k],pressed,now);
          } else if(rule->type==RULE_ON) {
            for(k=0;k<a_count;k++) set_relay(rule->value[4+key_count+k],1,now);
          } else {
            for(k=0;k<a_count;k++) set_relay(rule->value[4+key_count+k],0,now);
          }
          continue;
        }

        if(rule->type==RULE_ALLOFF) {
          a_count=rule->value[3+key_count];
          for(relay=0;relay<TOTAL_RELAYS;relay++) {
            skip=0;
            for(k=0;k<a_count;k++) if(relay==rule->value[4+key_count+k]) skip=1;
            if(!skip) set_relay(relay,0,now);
          }
          continue;
        }

        if(rule->type==RULE_3LEVEL) {
          a_count=rule->value[3+key_count];
          b_count=rule->value[4+key_count+a_count];
          a_on=0;
          b_on=0;
          for(k=0;k<a_count;k++) a_on+=relay_state[rule->value[4+key_count+k]];
          for(k=0;k<b_count;k++) b_on+=relay_state[rule->value[5+key_count+a_count+k]];
          if(key_last_release[event->key]==0) duration=LEVEL_INTERVAL_CS+1;
          else duration=event->time_cs-key_last_release[event->key];
          if(duration>LEVEL_INTERVAL_CS) {
            pressed=(a_on||b_on)?0:1;
            for(k=0;k<a_count;k++) set_relay(rule->value[4+key_count+k],pressed,now);
            for(k=0;k<b_count;k++) set_relay(rule->value[5+key_count+a_count+k],pressed,now);
          } else if(a_on&&b_on) {
            for(k=0;k<a_count;k++) set_relay(rule->value[4+key_count+k],1,now);
            for(k=0;k<b_count;k++) set_relay(rule->value[5+key_count+a_count+k],0,now);
          } else if(a_on&&!b_on) {
            for(k=0;k<a_count;k++) set_relay(rule->value[4+key_count+k],0,now);
            for(k=0;k<b_count;k++) set_relay(rule->value[5+key_count+a_count+k],1,now);
          } else if(!a_on&&b_on) {
            for(k=0;k<a_count;k++) set_relay(rule->value[4+key_count+k],0,now);
            for(k=0;k<b_count;k++) set_relay(rule->value[5+key_count+a_count+k],0,now);
          } else {
            for(k=0;k<a_count;k++) set_relay(rule->value[4+key_count+k],1,now);
            for(k=0;k<b_count;k++) set_relay(rule->value[5+key_count+a_count+k],1,now);
          }
          continue;
        }

        if(rule->type==RULE_3LIGHT) {
          a_count=rule->value[3+key_count];
          b_count=rule->value[4+key_count+a_count];
          c_count=rule->value[5+key_count+a_count+b_count];
          a_on=0;
          b_on=0;
          c_on=0;
          for(k=0;k<a_count;k++) a_on+=relay_state[rule->value[4+key_count+k]];
          for(k=0;k<b_count;k++) b_on+=relay_state[rule->value[5+key_count+a_count+k]];
          for(k=0;k<c_count;k++) c_on+=relay_state[rule->value[6+key_count+a_count+b_count+k]];
          if(key_last_release[event->key]==0) duration=LEVEL_INTERVAL_CS+1;
          else duration=event->time_cs-key_last_release[event->key];
          if(duration>LEVEL_INTERVAL_CS) {
            pressed=(a_on||b_on||c_on)?0:1;
            for(k=0;k<a_count;k++) set_relay(rule->value[4+key_count+k],pressed,now);
            for(k=0;k<b_count;k++) set_relay(rule->value[5+key_count+a_count+k],pressed,now);
            for(k=0;k<c_count;k++) set_relay(rule->value[6+key_count+a_count+b_count+k],pressed,now);
          } else if(a_on&&b_on&&c_on) {
            for(k=0;k<a_count;k++) set_relay(rule->value[4+key_count+k],1,now);
            for(k=0;k<b_count;k++) set_relay(rule->value[5+key_count+a_count+k],0,now);
            for(k=0;k<c_count;k++) set_relay(rule->value[6+key_count+a_count+b_count+k],0,now);
          } else if(a_on&&!b_on&&!c_on) {
            for(k=0;k<a_count;k++) set_relay(rule->value[4+key_count+k],0,now);
            for(k=0;k<b_count;k++) set_relay(rule->value[5+key_count+a_count+k],1,now);
            for(k=0;k<c_count;k++) set_relay(rule->value[6+key_count+a_count+b_count+k],0,now);
          } else if(!a_on&&b_on&&!c_on) {
            for(k=0;k<a_count;k++) set_relay(rule->value[4+key_count+k],0,now);
            for(k=0;k<b_count;k++) set_relay(rule->value[5+key_count+a_count+k],0,now);
            for(k=0;k<c_count;k++) set_relay(rule->value[6+key_count+a_count+b_count+k],1,now);
          } else if(!a_on&&!b_on&&c_on) {
            for(k=0;k<a_count;k++) set_relay(rule->value[4+key_count+k],0,now);
            for(k=0;k<b_count;k++) set_relay(rule->value[5+key_count+a_count+k],0,now);
            for(k=0;k<c_count;k++) set_relay(rule->value[6+key_count+a_count+b_count+k],0,now);
          } else {
            for(k=0;k<a_count;k++) set_relay(rule->value[4+key_count+k],1,now);
            for(k=0;k<b_count;k++) set_relay(rule->value[5+key_count+a_count+k],1,now);
            for(k=0;k<c_count;k++) set_relay(rule->value[6+key_count+a_count+b_count+k],1,now);
          }
        }
      }
    }
  }
}

static void update_key_times(void) {
  int i;
  int key;

  for(i=0;i<event_count;i++) {
    key=event_list[i].key;
    if(!event_list[i].state) key_last_release[key]=event_list[i].time_cs;
  }
}

static int send_bem_outputs(int first_relay, const char *ip) {
  char message[128];
  int fd;
  int relay;
  int used;
  int changed;

  used=0;
  changed=0;
  for(relay=first_relay;relay<first_relay+8;relay++) {
    if(relay_state[relay]==relay_old[relay]) continue;
    used+=sprintf(message+used,"k0%c=%c;",'1'+relay-first_relay,'0'+relay_state[relay]);
    relay_old[relay]=relay_state[relay];
    changed=1;
  }
  if(!changed) return 0;
  fd=connect_tcp(ip,5000);
  if(fd<0) return -1;
  if(send_all(fd,message,used)!=0) {
    close(fd);
    return -1;
  }
  close(fd);
  return 0;
}

static void write_outputs(void) {
  unsigned char value_a;
  unsigned char value_b;
  unsigned char changed_a;
  unsigned char changed_b;
  char stamp[32];
  int dev;
  int i;
  int relay;

  for(dev=0;dev<BOARD_COUNT;dev++) {
    value_a=0;
    value_b=0;
    changed_a=0;
    changed_b=0;
    for(i=0;i<12;i++) {
      relay=dev*12+i;
      if(relay_state[relay]!=relay_old[relay]) {
        wall_time_string(stamp,sizeof(stamp));
        log_message("out: %02d %01d %s\n",relay,relay_state[relay],stamp);
        if(i<8) changed_a=1;
        else changed_b=1;
      }
      if(relay_state[relay]) {
        if(i<8) value_a=(unsigned char)(value_a|(1U<<i));
        else value_b=(unsigned char)(value_b|(1U<<(i-4)));
      }
      relay_old[relay]=relay_state[relay];
    }
    if(changed_a) send_board_command(dev,0x43,value_a);
    if(changed_a) scan_delay();
    if(changed_b) send_board_command(dev,0x46,value_b);
    if(changed_b) scan_delay();
  }

  for(relay=48;relay<64;relay++) {
    if(relay_state[relay]==relay_old[relay]) continue;
    wall_time_string(stamp,sizeof(stamp));
    log_message("out: %02d %01d %s\n",relay,relay_state[relay],stamp);
  }
  send_bem_outputs(48,bem_output_ip[0]);
  send_bem_outputs(56,bem_output_ip[1]);
}

static int rule_has_key(const Rule *rule, int key) {
  int i;
  int count;

  if(rule->type<0||rule->type==RULE_OFF_TIMED) return 0;
  if(rule->type==RULE_INJECT_IF_OFF||rule->type==RULE_INJECT_IF_ON) return rule->value[2]==key;
  count=rule->value[2];
  for(i=0;i<count;i++) if(rule->value[3+i]==key) return 1;
  return 0;
}

static int rule_has_relay(const Rule *rule, int relay) {
  int key_count;
  int a_count;
  int b_count;
  int c_count;
  int i;

  if(rule->type<0) return 0;
  if(rule->type==RULE_INJECT_IF_OFF||rule->type==RULE_INJECT_IF_ON) return rule->value[3]==relay;
  if(rule->type==RULE_OFF_TIMED) return rule->value[2]==relay;
  if(rule->type==RULE_OFF_TIMED_KEYSUP) {
    key_count=rule->value[2];
    return rule->value[3+key_count]==relay;
  }
  key_count=rule->value[2];
  a_count=rule->value[3+key_count];
  for(i=0;i<a_count;i++) if(rule->value[4+key_count+i]==relay) return 1;
  if(rule->type==RULE_3LEVEL||rule->type==RULE_3LIGHT) {
    b_count=rule->value[4+key_count+a_count];
    for(i=0;i<b_count;i++) if(rule->value[5+key_count+a_count+i]==relay) return 1;
    if(rule->type==RULE_3LIGHT) {
      c_count=rule->value[5+key_count+a_count+b_count];
      for(i=0;i<c_count;i++) {
        if(rule->value[6+key_count+a_count+b_count+i]==relay) return 1;
      }
    }
  }
  return 0;
}

static void show_rule(Text *text, int index, const Rule *rule) {
  int key_count;
  int a_count;
  int b_count;
  int c_count;
  int i;
  int relay;

  text_addf(text,"Rule: %02d Type: <i>%s</i> Name: <b>%s</b>\n",
    index,rule_type_name(rule->type),rule->name);
  if(rule->type<0) {
    text_add(text,"\n");
    return;
  }
  if(rule->type==RULE_INJECT_IF_OFF||rule->type==RULE_INJECT_IF_ON) {
    text_addf(text,"HH: %02d, MM: %02d\n",rule->value[0],rule->value[1]);
    text_addf(text,"Key: %02d Relay: %02d\n\n",rule->value[2],rule->value[3]);
    return;
  }
  if(rule->type==RULE_OFF_TIMED) {
    text_addf(text,"HH_start: %02d, HH_end: %02d\n",rule->value[0],rule->value[1]);
    text_addf(text,"Relayoff: %02d After(min): %02d\n\n",rule->value[2],rule->value[3]);
    return;
  }
  if(rule->type==RULE_OFF_TIMED_KEYSUP) {
    key_count=rule->value[2];
    text_addf(text,"HH_start: %02d, HH_end: %02d\n",rule->value[0],rule->value[1]);
    text_addf(text,"Relayoff: %02d After(min): %02d\n",rule->value[3+key_count],rule->value[4+key_count]);
    text_addf(text,"Key #:%02d",key_count);
    for(i=0;i<key_count;i++) text_addf(text," %02d:%02d",i,rule->value[3+i]);
    text_add(text,"\n\n");
    return;
  }
  key_count=rule->value[2];
  text_addf(text,"HH_start: %02d, HH_end: %02d\n",rule->value[0],rule->value[1]);
  text_addf(text,"Key #:%02d",key_count);
  for(i=0;i<key_count;i++) text_addf(text," %02d:%02d",i,rule->value[3+i]);
  text_add(text,"\n");
  a_count=rule->value[3+key_count];
  if(rule->type==RULE_3LEVEL||rule->type==RULE_3LIGHT) text_addf(text,"Relay_A #:%02d",a_count);
  else if(rule->type==RULE_ALLOFF) text_addf(text,"Skip relay #:%02d",a_count);
  else text_addf(text,"Relay #:%02d",a_count);
  for(i=0;i<a_count;i++) {
    relay=rule->value[4+key_count+i];
    if(relay_state[relay]) text_addf(text," %02d:<b style='color:red;'>%02d</b>",i,relay);
    else text_addf(text," %02d:%02d",i,relay);
  }
  text_add(text,"\n");
  if(rule->type==RULE_3LEVEL||rule->type==RULE_3LIGHT) {
    b_count=rule->value[4+key_count+a_count];
    text_addf(text,"Relay_B #:%02d",b_count);
    for(i=0;i<b_count;i++) {
      relay=rule->value[5+key_count+a_count+i];
      if(relay_state[relay]) text_addf(text," %02d:<b style='color:red;'>%02d</b>",i,relay);
      else text_addf(text," %02d:%02d",i,relay);
    }
    text_add(text,"\n");
    if(rule->type==RULE_3LIGHT) {
      c_count=rule->value[5+key_count+a_count+b_count];
      text_addf(text,"Relay_C #:%02d",c_count);
      for(i=0;i<c_count;i++) {
        relay=rule->value[6+key_count+a_count+b_count+i];
        if(relay_state[relay]) text_addf(text," %02d:<b style='color:red;'>%02d</b>",i,relay);
        else text_addf(text," %02d:%02d",i,relay);
      }
      text_add(text,"\n");
    }
  }
  text_add(text,"\n");
}

static void append_log_reverse(Text *text, int lines) {
  FILE *fp;
  char line[LOG_LINE_SIZE];
  long end;
  long pos;
  long line_end;
  long start;
  long length;
  int count;
  int c;

  if(log_fp!=NULL) fflush(log_fp);
  fp=fopen(config_data.log_path,"rb");
  if(fp==NULL) {
    text_addf(text,"Cannot open log: %s\n",strerror(errno));
    return;
  }
  if(fseek(fp,0,SEEK_END)!=0) {
    fclose(fp);
    return;
  }
  end=ftell(fp);
  if(end<=0) {
    fclose(fp);
    return;
  }
  line_end=end;
  pos=end-1;
  if(fseek(fp,pos,SEEK_SET)==0&&fgetc(fp)=='\n') {
    line_end=pos;
    pos--;
  }
  count=0;
  for(;pos>=0&&count<lines;pos--) {
    if(fseek(fp,pos,SEEK_SET)!=0) break;
    c=fgetc(fp);
    if(c!='\n') continue;
    start=pos+1;
    length=line_end-start;
    if(length>0) {
      if(length>LOG_LINE_SIZE-2) length=LOG_LINE_SIZE-2;
      if(fseek(fp,start,SEEK_SET)!=0) break;
      length=(long)fread(line,1,(size_t)length,fp);
      line[length]='\0';
      text_add(text,line);
      text_add(text,"\n");
      count++;
    }
    line_end=pos;
  }
  if(count<lines&&line_end>0) {
    length=line_end;
    if(length>LOG_LINE_SIZE-2) length=LOG_LINE_SIZE-2;
    if(fseek(fp,0,SEEK_SET)==0) {
      length=(long)fread(line,1,(size_t)length,fp);
      line[length]='\0';
      text_add(text,line);
      text_add(text,"\n");
    }
  }
  fclose(fp);
}

static int reload_config(Text *text) {
  Config fresh;
  FILE *new_log;
  char error[CONFIG_LINE_SIZE];
  int log_changed;

  if(load_config(CONFIG_FILE,&fresh,error,sizeof(error))!=0) {
    text_addf(text,"Configuration error: %s\n",error);
    return -1;
  }
  log_changed=strcmp(fresh.log_path,config_data.log_path)!=0;
  new_log=NULL;
  if(log_changed&&open_log(fresh.log_path,&new_log)!=0) {
    text_addf(text,"Cannot open new log %s: %s\n",fresh.log_path,strerror(errno));
    return -1;
  }
  config_data=fresh;
  if(log_changed) {
    if(log_fp!=NULL) fclose(log_fp);
    log_fp=new_log;
  }
  text_addf(text,"Load Rule_v:%s #rules:%d\n",config_data.version,config_data.rule_count);
  return 0;
}

static void command_status(Text *text) {
  int relay;
  int count;

  text_add(text,"<b>Relay Status</b>\n");
  count=0;
  for(relay=0;relay<TOTAL_RELAYS;relay++) {
    if(relay_state[relay]) {
      text_addf(text,"%02d:<b style='color:red;'>1</b> ",relay);
      count++;
    } else text_addf(text,"%02d:0 ",relay);
    if(relay%8==7) text_add(text,"\n");
  }
  text_addf(text,"Total On: <b>%d</b>\n",count);
}

static void command_keystatus(Text *text) {
  int key;
  int count;

  text_add(text,"<b>Key Status</b>\n");
  count=0;
  for(key=0;key<PHYSICAL_KEYS;key++) {
    if(key_down[key]) {
      text_addf(text,"%02d:<b style='color:red;'>1</b> ",key);
      count++;
    } else text_addf(text,"%02d:0 ",key);
    if(key%8==7) text_add(text,"\n");
  }
  text_addf(text,"Total Pressed: <b>%d</b>\n",count);
}

static void command_rules(Text *text) {
  int i;

  text_add(text,"<b>Rule list</b>\n");
  for(i=0;i<config_data.rule_count;i++) show_rule(text,i,&config_data.rule[i]);
}

static void command_keys(Text *text) {
  int key;
  int rule;
  int count;

  text_add(text,"<b>Keys associations</b>\n");
  for(key=0;key<TOTAL_KEYS;key++) {
    text_addf(text,"Key #:%02d",key);
    count=0;
    for(rule=0;rule<config_data.rule_count;rule++) {
      if(!rule_has_key(&config_data.rule[rule],key)) continue;
      text_addf(text," %02d:%02d(%s)",count,rule,config_data.rule[rule].name);
      count++;
    }
    text_add(text,"\n");
  }
}

static void command_relays(Text *text) {
  int relay;
  int rule;
  int count;

  text_add(text,"<b>Relays associations</b>\n");
  for(relay=0;relay<TOTAL_RELAYS;relay++) {
    if(relay_state[relay]) text_addf(text,"Relay #:<b style='color:red;'>%02d</b>",relay);
    else text_addf(text,"Relay #:%02d",relay);
    count=0;
    for(rule=0;rule<config_data.rule_count;rule++) {
      if(!rule_has_relay(&config_data.rule[rule],relay)) continue;
      text_addf(text," %02d:%02d(%s)",count,rule,config_data.rule[rule].name);
      count++;
    }
    text_add(text,"\n");
  }
}

static void command_help(Text *text) {
  text_add(text,"/passwd/status show the status\n");
  text_add(text,"/passwd/keystatus show the keys status\n");
  text_add(text,"/passwd/inject/n inject key n\n");
  text_add(text,"/passwd/set/n set relay n\n");
  text_add(text,"/passwd/reset/n reset relay n\n");
  text_add(text,"/passwd/switchoff reset all relays\n");
  text_add(text,"/passwd/rule display actual rules\n");
  text_add(text,"/passwd/key display keys mapping on rules\n");
  text_add(text,"/passwd/relay display relays mapping on rules\n");
  text_add(text,"/passwd/log/n log last n lines\n");
  text_add(text,"/passwd/reload reload configuration\n");
  text_add(text,"/passwd/delete/n delete rule n until reload\n");
  text_add(text,"/passwd/keyoff key deactivation\n");
  text_add(text,"/passwd/keyon key activation\n");
  text_add(text,"/passwd/help this help\n");
}

static void handle_command(Text *text, char *path, const char *request_line) {
  char *password;
  char *command;
  char *argument;
  char *extra;
  struct tm *local;
  time_t now_time;
  unsigned long now;
  long number;
  int relay;
  int i;

  password=strtok(path,"/");
  command=strtok(NULL,"/");
  argument=strtok(NULL,"/");
  extra=strtok(NULL,"/");
  if(password==NULL||command==NULL||extra!=NULL||strcmp(password,PASSWORD)!=0) {
    text_add(text,"Wrong Parameters\n");
    text_add(text,request_line);
    text_add(text,"\n");
    return;
  }
  now_time=time(NULL);
  local=localtime(&now_time);
  now=monotonic_cs();
  text_addf(text,"<i>Casa_v:%s Rule_v:%s #rules:%d Keyoff:%d</i>\n",
    PROGRAM_VERSION,config_data.version,config_data.rule_count,keyoff);
  if(local!=NULL) text_addf(text,"<i>hh:%02d mm:%02d uptime_cs:%lu</i>\n",
    local->tm_hour,local->tm_min,now);

  if(strcmp(command,"status")==0&&argument==NULL) {
    command_status(text);
  } else if(strcmp(command,"keystatus")==0&&argument==NULL) {
    command_keystatus(text);
  } else if(strcmp(command,"keyoff")==0&&argument==NULL) {
    keyoff=1;
    text_add(text,"Key set to off\n");
  } else if(strcmp(command,"keyon")==0&&argument==NULL) {
    keyoff=0;
    text_add(text,"Key set to on\n");
  } else if(strcmp(command,"inject")==0&&argument!=NULL&&
    parse_number(argument,0,TOTAL_KEYS-1,&number)==0) {
    inject_key((int)number,now);
    text_addf(text,"Inject key <b>%ld</b>\n",number);
  } else if(strcmp(command,"set")==0&&argument!=NULL&&
    parse_number(argument,0,TOTAL_RELAYS-1,&number)==0) {
    set_relay((int)number,1,now);
    text_addf(text,"Set relay <b>%ld</b>\n",number);
  } else if(strcmp(command,"reset")==0&&argument!=NULL&&
    parse_number(argument,0,TOTAL_RELAYS-1,&number)==0) {
    set_relay((int)number,0,now);
    text_addf(text,"Reset relay <b>%ld</b>\n",number);
  } else if(strcmp(command,"delete")==0&&argument!=NULL&&
    parse_number(argument,0,config_data.rule_count-1,&number)==0) {
    config_data.rule[number].type=-1;
    text_addf(text,"Delete rule <b>%ld</b>\n",number);
  } else if(strcmp(command,"switchoff")==0&&argument==NULL) {
    for(relay=0;relay<TOTAL_RELAYS;relay++) set_relay(relay,0,now);
    text_add(text,"Reset relay all\n");
  } else if(strcmp(command,"rule")==0&&argument==NULL) {
    command_rules(text);
  } else if(strcmp(command,"key")==0&&argument==NULL) {
    command_keys(text);
  } else if(strcmp(command,"relay")==0&&argument==NULL) {
    command_relays(text);
  } else if(strcmp(command,"log")==0&&argument!=NULL&&
    parse_number(argument,1,1000,&number)==0) {
    text_addf(text,"<b>Log of last %ld actions</b>\n",number);
    append_log_reverse(text,(int)number);
  } else if(strcmp(command,"reload")==0&&argument==NULL) {
    reload_config(text);
  } else if(strcmp(command,"help")==0&&argument==NULL) {
    command_help(text);
  } else {
    text_add(text,"<i>Wrong Command</i>\n");
  }

  i=0;
  if(i) text_add(text,"");
}

static void handle_client(int fd) {
  char request[HTTP_REQUEST_SIZE];
  char path[HTTP_REQUEST_SIZE];
  char header[256];
  char *line_end;
  char *path_end;
  ssize_t received;
  int used;

  used=0;
  for(;used<(int)sizeof(request)-1;) {
    received=recv(fd,request+used,sizeof(request)-1-(size_t)used,0);
    if(received<0&&errno==EINTR) continue;
    if(received<=0) break;
    used+=(int)received;
    request[used]='\0';
    if(strstr(request,"\r\n")!=NULL||strchr(request,'\n')!=NULL) break;
  }
  request[used]='\0';
  text_clear(&http_body);
  text_add(&http_body,"<html><body style='background-color:#F9F4B7'><pre>");
  if(strncmp(request,"GET ",4)!=0) {
    text_add(&http_body,"Wrong Parameters\n");
  } else {
    line_end=strstr(request,"\r\n");
    if(line_end==NULL) line_end=strchr(request,'\n');
    if(line_end!=NULL) *line_end='\0';
    path_end=strchr(request+4,' ');
    if(path_end==NULL||(unsigned long)(path_end-(request+4))>=sizeof(path)) {
      text_add(&http_body,"Wrong Parameters\n");
    } else {
      memcpy(path,request+4,(size_t)(path_end-(request+4)));
      path[path_end-(request+4)]='\0';
      handle_command(&http_body,path,request);
    }
  }
  text_add(&http_body,"</pre></body></html>");
  sprintf(header,
    "HTTP/1.1 200 OK\r\nCache-Control: no-cache\r\nContent-Type: text/html\r\nContent-Length: %lu\r\nConnection: Close\r\n\r\n",
    http_body.len);
  send_all(fd,header,(int)strlen(header));
  send_all(fd,http_body.data,(int)http_body.len);
}

static void service_http(void) {
  struct sockaddr_in address;
  struct timeval timeout;
  socklen_t length;
  int fd;
  int i;

  for(i=0;i<8;i++) {
    length=sizeof(address);
    fd=accept(server_fd,(struct sockaddr *)&address,&length);
    if(fd<0) {
      if(errno==EINTR) continue;
      break;
    }
    timeout.tv_sec=0;
    timeout.tv_usec=SOCKET_TIMEOUT_MS*1000;
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    handle_client(fd);
    close(fd);
  }
}

static void cleanup(void) {
  int dev;

  if(server_fd>=0) close(server_fd);
  server_fd=-1;
  for(dev=0;dev<INPUT_DEVICE_COUNT;dev++) close_input(dev);
  if(log_fp!=NULL) fclose(log_fp);
  log_fp=NULL;
}

int main(void) {
  char error[CONFIG_LINE_SIZE];
  char stamp[32];
  struct tm *local;
  time_t wall;
  unsigned long now;
  long minute_id;
  long last_minute;
  int hour;
  int minute;
  int i;

  for(i=0;i<INPUT_DEVICE_COUNT;i++) input_fd[i]=-1;
  for(i=0;i<INPUT_DEVICE_COUNT;i++) input_old[i]=0xffff;
  for(i=0;i<TOTAL_RELAYS;i++) relay_time[i]=0;
  server_fd=-1;
  log_fp=NULL;
  event_count=0;
  inject_count=0;
  keyoff=0;
  if(load_config(CONFIG_FILE,&config_data,error,sizeof(error))!=0) {
    fprintf(stderr,"Configuration error: %s\n",error);
    return 1;
  }
  if(open_log(config_data.log_path,&log_fp)!=0) {
    fprintf(stderr,"Cannot open log %s: %s\n",config_data.log_path,strerror(errno));
    return 1;
  }
  signal(SIGPIPE,SIG_IGN);
  signal(SIGINT,stop_program);
  signal(SIGTERM,stop_program);
  server_fd=open_server();
  if(server_fd<0) {
    fprintf(stderr,"Cannot listen on %s:%d: %s\n",LISTEN_IP,LISTEN_PORT,strerror(errno));
    cleanup();
    return 1;
  }
  now=monotonic_cs();
  for(i=0;i<TOTAL_RELAYS;i++) relay_time[i]=now;
  wall_time_string(stamp,sizeof(stamp));
  log_message("Casa:%s, Config:%s, #Rules:%d, Creator GM\n",
    PROGRAM_VERSION,config_data.version,config_data.rule_count);
  log_message("Starting on %s\n",stamp);
  initialize_hardware();
  last_minute=-1;

  for(;running;) {
    now=monotonic_cs();
    event_count=0;
    read_inputs();
    scan_keys(now);
    release_injected(now);

    wall=time(NULL);
    local=localtime(&wall);
    hour=0;
    minute=0;
    minute_id=0;
    if(local!=NULL) {
      hour=local->tm_hour;
      minute=local->tm_min;
      minute_id=(long)(wall/60);
    }
    if(minute_id!=last_minute) {
      last_minute=minute_id;
      process_timed_rules(hour,minute,now);
    }

    service_http();
    if(event_count) process_actions(hour,now);
    write_outputs();
    update_key_times();
  }

  cleanup();
  return 0;
}
