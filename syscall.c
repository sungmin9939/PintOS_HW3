#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

#define MAX_ARGS 3


static void syscall_handler (struct intr_frame *);

void sysexit (int status);
pid_t sysexec(const char* cmdline);
bool syscreate(const char* file_name, unsigned starting_size);
bool sysremove(const char* file_name);
int sysopen(const char * file_name);
int sysfilesize(int filedes);
int sysread(int filedes, void *buffer, unsigned length);
int syswrite (int filedes, const void * buffer, unsigned byte_size);
void sysseek (int filedes, unsigned new_position);
unsigned systell(int fildes);
void sysclose(int filedes);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  
  int arg[MAX_ARGS];
  int esp = getpage_ptr((const void *) f->esp);
  
  switch (* (int *) esp)
  {
    case SYS_HALT:
      shutdown_power_off();
      break;
      
    case SYS_EXIT:
      sysexit(*((int *) f->esp + 1));
      break;
      
    case SYS_EXEC:
      arg[0] = getpage_ptr((const void *)*((int *) f->esp + 1));
      f->eax = sysexec((const char*)arg[0]);
      break;
      
    case SYS_WAIT:
      f->eax = process_wait(*((int *) f->esp + 1));
      break;
      
    case SYS_CREATE:
      arg[0] = getpage_ptr((const void *)*((int *) f->esp + 1));
      f->eax = syscreate((const char *)arg[0], (unsigned)*((int *) f->esp + 2));
      break;
      
    case SYS_REMOVE:
      arg[0] = getpage_ptr((const void *)*((int *) f->esp + 1));
      f->eax = sysremove((const char *)arg[0]);
      break;
      
    case SYS_OPEN:
      arg[0] = getpage_ptr((const void *)*((int *) f->esp + 1));
      f->eax = sysopen((const char *)arg[0]); 
      break;
      
    case SYS_FILESIZE:
      f->eax = sysfilesize(*((int *) f->esp + 1));
      break;
      
    case SYS_READ:
      arg[1] = getpage_ptr((const void *)*((int *) f->esp + 2));
      f->eax = sysread(*((int *) f->esp + 1), (void *) arg[1], (unsigned)*((int *) f->esp + 3));
      break;
      
    case SYS_WRITE:
      arg[1] = getpage_ptr((const void *)*((int *) f->esp + 2)); 
      f->eax = syswrite(*((int *) f->esp + 1), (const void *) arg[1], (unsigned)*((int *) f->esp + 3));
      break;
      
    case SYS_SEEK:
      sysseek(*((int *) f->esp + 1), (unsigned)*((int *) f->esp + 2));
      break;
      
    case SYS_TELL:
      f->eax = systell(*((int *) f->esp + 1));
      break;
    
    case SYS_CLOSE:
      sysclose(*((int *) f->esp + 1));
      break;
      
    default:
      break;
  }
}

void sysexit (int status)
{
  struct thread *cur = thread_current();
  if (check_live_thread(cur->parent) )
  {
    if (status < 0)
    {
      status = -1;
    }
    cur->cp->status = status;
  }
  printf("%s: exit(%d)\n", cur->name, status);
  thread_exit();
}

pid_t sysexec(const char* cmdline)
{
    pid_t pid = process_execute(cmdline);
    return pid;
}

bool syscreate(const char* file_name, unsigned starting_size)
{
  bool successful = filesys_create(file_name, starting_size);
  return successful;
}

bool sysremove(const char* file_name)
{
  bool successful = filesys_remove(file_name);
  return successful;
}

int sysopen(const char *file_name)
{
  struct file *file_ptr = filesys_open(file_name);
  struct process_file *process_file_ptr = malloc(sizeof(struct process_file));
  if (!file_ptr)
  {
    return -1;
  }
  process_file_ptr->file = file_ptr;
  process_file_ptr->fd = thread_current()->fd;
  thread_current()->fd++;
  list_push_back(&thread_current()->file_list, &process_file_ptr->elem);

  int filedes = process_file_ptr->fd;
  return filedes;
}

int sysfilesize(int filedes)
{
  struct file *file_ptr = get_file(filedes);
  if (!file_ptr)
  {
    return -1;
  }
  int filesize = file_length(file_ptr);
  return filesize;
}

int sysread(int filedes, void *buffer, unsigned length)
{
  if (length <= 0)
  {
    return length;
  }
  
  struct file *file_ptr = get_file(filedes);
  if (!file_ptr)
  {
    return -1;
  }
  int bytes_read = file_read(file_ptr, buffer, length);
  return bytes_read;
}

int syswrite (int filedes, const void * buffer, unsigned length)
{
  if (length <= 0)
  {
    return length;
  }
  if (filedes == 1)
  {
    putbuf (buffer, length);
    return length;
  }

  struct file *file_ptr = get_file(filedes);
  if (!file_ptr)
  {
    return -1;
  }
  int bytes_write = file_write(file_ptr, buffer, length);
  return bytes_write;
}

void sysseek (int filedes, unsigned new_position)
{
  struct file *file_ptr = get_file(filedes);
  if (!file_ptr)
  {
    return;
  }
  file_seek(file_ptr, new_position);
}

unsigned systell(int filedes)
{
  struct file *file_ptr = get_file(filedes);
  if (!file_ptr)
  {
    return -1;
  }
  off_t offset = file_tell(file_ptr);
  return offset;
}

void sysclose(int filedes)
{
  struct thread *t = thread_current();
  struct list_elem *next;
  struct list_elem *e = list_begin(&t->file_list);
  
  for (;e != list_end(&t->file_list); e = next)
  {
    next = list_next(e);
    struct process_file *process_file_ptr = list_entry (e, struct process_file, elem);
    if (filedes == process_file_ptr->fd || filedes == -1)
    {
      file_close(process_file_ptr->file);
      list_remove(&process_file_ptr->elem);
      free(process_file_ptr);
      if (filedes != -1)
      {
        return;
      }
    }
  }
}

int getpage_ptr(const void *vaddr)
{
  void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
  if (!ptr)
  {
    sysexit(-1);
  }
  return (int)ptr;
}

struct child_process* find_child_process(int pid)
{
  struct thread *t = thread_current();
  struct list_elem *e;
  struct list_elem *next;
  
  for (e = list_begin(&t->child_list); e != list_end(&t->child_list); e = next)
  {
    next = list_next(e);
    struct child_process *cp = list_entry(e, struct child_process, elem);
    if (pid == cp->pid)
    {
      return cp;
    }
  }
  return NULL;
}

struct file* get_file (int filedes)
{
  struct thread *t = thread_current();
  struct list_elem* next;
  struct list_elem* e = list_begin(&t->file_list);
  
  for (; e != list_end(&t->file_list); e = next)
  {
    next = list_next(e);
    struct process_file *process_file_ptr = list_entry(e, struct process_file, elem);
    if (filedes == process_file_ptr->fd)
    {
      return process_file_ptr->file;
    }
  }
  return NULL;
}