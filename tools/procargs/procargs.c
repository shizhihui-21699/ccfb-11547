#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
int main(int c,char**v){ pid_t pid=atoi(v[1]); size_t sz=0; int mib[3]={CTL_KERN,KERN_PROCARGS2,pid};
 if(sysctl(mib,3,NULL,&sz,0,0)){perror("sz");return 1;} char*b=malloc(sz); if(sysctl(mib,3,b,&sz,0,0)){perror("read");return 1;}
 int argc=*(int*)b; char*p=b+sizeof(int); int hits=0;
 for(int i=0;i<argc;i++){ while(p<b+sz&&*p)p++; while(p<b+sz&&!*p)p++; }
 for(;p<b+sz;p+=strlen(p)+1){ if(*p && strstr(p,v[2])) { hits++; printf("  found: %.60s\n", p); } }
 printf("  '%s' occurrences in KERN_PROCARGS2: %d\n", v[2], hits); return 0; }
