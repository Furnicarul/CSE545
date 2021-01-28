// compile with -no-pie
// gcc ./gym.c -no-pie -g -o ./gym
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#define MALLOC "m"
#define FREE "f"
#define LIST "l"
#define EDIT "e"
#define EXIT "exit"

#define FREED 0
#define UNDERUSE 1

void* ptrs[100];
int used[100] = {0};
int request_size[100] = {0};
int cnt = 0;

void print_menu(){
  char *MENU[6] = {
    "Choose from the following menu:\n",
    "0. [exit]\n",
    "1. [m]alloc with size, e.g. m 2\n",
    "2. [f]ree with index, e.g, f 1\n",
    "3. [e]dit allocated chunk's content, e.g, e 2\n",
    "4. [l]ist all pointers, e.g, l\n"};

  for(int i = 0; i < 6; i++)
    printf("%s", MENU[i]);
}

void act_malloc(int n){
  printf("Allocating %d bytes\n", n);
  ptrs[cnt] = malloc(n);
  used[cnt] = UNDERUSE;
  request_size[cnt] = n;
  cnt++;
}

void act_free(int n){
  printf("Freeing pointer %d: %p\n", n, ptrs[n]);
  free(ptrs[n]);
  used[n] = FREED;
}

void act_edit(int n, char *s){
  // this is a overflow vulnerability that we will talk about in future classes
  printf("Editing pointer %d: %p\n", n, ptrs[n]);
  int l1 = strlen(ptrs[n]);
  int l2 = strlen(s);
  int l;
  if (l1 < l2) l = l2;
  else l = l1;
  memcpy(ptrs[n], s, l);
}

void list_ptrs(){
  printf("Index\tPointers\tRequested Size\tStatus\n");
  for (int i = 0; i < cnt; i++){
    printf("%d\t%p\t%u\t", i, ptrs[i], request_size[i]);
    if (used[i] == UNDERUSE)
      printf("Under Use\n");
    else if (used[i] == FREED)
      printf("Freed\n");
  }
}

int valid_id(char *s, ssize_t len){
  ssize_t i = 0;
  for (i = 0; i < len; i++)
    if (!isdigit(s[i]) && !isalpha(s[i]))
      return 0;
  return 1;
}

void win(){
  char *buf = NULL;
  size_t size = 0;
  ssize_t len = 0;
  char path[50] = "records/";
  FILE *fd;

  printf("What's your ASURITE?\n");
  len = getline(&buf, &size, stdin);
  buf[len - 1] = 0;
  if (valid_id(buf, len - 1) == 1){
    strncat(path, buf, len - 1);
    fd = fopen(path, "w");
    fclose(fd);
    printf("Your ID is logged\n");
  }
  exit(0);
}

int main(){
  char buf[100];
  char str[100];
  int n;
  setbuf(stdout, NULL);
  while (1){
    print_menu();
    memset(buf, 0, 100);
    read(0, buf, 90);
    if (strstr(buf, MALLOC) || buf[0] == '1'){
      sscanf(buf + sizeof(MALLOC), "%d", &n);
      act_malloc(n);
    }
    else if (strstr(buf, FREE) || buf[0] == '2'){
      sscanf(buf + sizeof(FREE), "%d", &n);
      act_free(n);
    }
    else if (strstr(buf, EDIT) || buf[0] == '3'){
      sscanf(buf + sizeof(EDIT), "%d %[^\n]", &n, str);
      act_edit(n, str);
    }
    else if (strstr(buf, LIST) || buf[0] == '4')
      list_ptrs();
    else if (strstr(buf, EXIT) || buf[0] == '0')
      break;
    else continue;
  }
  return 0;
}
