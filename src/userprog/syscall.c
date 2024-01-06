#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "userprog/process.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "lib/kernel/list.h"

#ifdef DEBUG
#define _DEBUG_PRINTF(...) printf(__VA_ARGS__) // this means we pass the same asgument
#else
#define _DEBUG_PRINTF(...) /* do nothing */
#endif

static struct file_desc* find_file_desc(int fd);
static void syscall_handler (struct intr_frame *);
static int memread_user (void *src, void *dst, size_t bytes);
void sys_halt (void);
void sys_exit (int);
static int32_t get_user (const uint8_t *uaddr);
pid_t sys_exec (const char *cmd_line);
int sys_wait(pid_t pid);
bool sys_write(int fd, const void *buffer, unsigned size, int* ret);
bool sys_remove(const char *file);
static int fail_invalid_access(void);
bool sys_create(const char* file, unsigned initial_size);
int sys_open(const char* file);
void sys_close(int fd);
int sys_filesize(int fd);

struct lock filesys_lock;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  // Variable to store the system call number.
  int syscall_number;
  ASSERT( sizeof(syscall_number) == 4 ); // assuming x86

  // The system call number is in the 32-bit word at the caller's stack pointer.
  if (memread_user(f->esp, &syscall_number, sizeof(syscall_number)) == -1) {
    fail_invalid_access(); // invalid memory access, terminate the user process
    return;
  }

  _DEBUG_PRINTF ("[DEBUG] system call, number = %d!\n", syscall_number);

  // The following cases are placeholders for additional system calls,
  // which need to be implemented and handled similarly to SYS_HALT and SYS_EXIT.
  switch (syscall_number) {
  case SYS_HALT:
    {
      sys_halt();
      NOT_REACHED();
      break;
    }

  case SYS_EXIT:
    {
      int exitcode;
      if (memread_user(f->esp + 4, &exitcode, sizeof(exitcode)) == -1)
        fail_invalid_access(); // invalid memory access

      sys_exit(exitcode);
      NOT_REACHED();
      break;
    }

  case SYS_EXEC:
    {
      void* cmd_line;
      // assign command line to cmd_line while checking if read is successful
      if (memread_user(f->esp + 4, &cmd_line, sizeof(cmd_line)) == -1) 
        fail_invalid_access();

      int return_code = sys_exec((const char*) cmd_line);
      f->eax = (uint32_t) return_code;
      break;
    }

  case SYS_WAIT: // 3
    {
      pid_t pid;
      if (memread_user(f->esp + 4, &pid, sizeof(pid_t)) == -1)
        fail_invalid_access();

      int ret = sys_wait(pid);
      f->eax = (uint32_t) ret;
      break;
    }  
  case SYS_CREATE:
    {
      const char* file;
      unsigned initial_size;
      bool return_code;
      if (memread_user(f->esp + 4, &file, sizeof(file)) == -1)
          fail_invalid_access(); // invalid memory access
      if (memread_user(f->esp + 8, &initial_size, sizeof(initial_size)) == -1)
          fail_invalid_access(); // invalid memory access

      return_code = sys_create(file, initial_size);
      f->eax = return_code;
      break;
    }
  case SYS_REMOVE:
    goto unhandled;
  case SYS_READ:
    goto unhandled;
  case SYS_WRITE:
    {
    int fd, return_code;
    const void *buffer;
    unsigned size;

    // assign values appropriately and do some sanity checks
    if(-1 == memread_user(f->esp + 4, &fd, 4)) fail_invalid_access();
    if(-1 == memread_user(f->esp + 8, &buffer, 4)) fail_invalid_access();
    if(-1 == memread_user(f->esp + 12, &size, 4)) fail_invalid_access();

    if(!sys_write(fd, buffer, size, &return_code)) thread_exit();
    f->eax = (uint32_t) return_code;
    break;
  }
  case SYS_OPEN:
      {
      const char* filename;
      int return_code;

      if (memread_user(f->esp + 4, &filename, sizeof(filename)) == -1)
         fail_invalid_access(); // invalid memory access
      return_code = sys_open(filename);
      f->eax = return_code;
      break;
    }
  case SYS_FILESIZE:
    {
      int fd, return_code;
      if (memread_user(f->esp + 4, &fd, sizeof(fd)) == -1)
         fail_invalid_access(); // invalid memory access

      return_code = sys_filesize(fd);
      f->eax = return_code;
      break;
    }

  case SYS_SEEK:
  case SYS_TELL:
    goto unhandled;
  case SYS_CLOSE:
    {
      int fd;
      if (memread_user(f->esp + 4, &fd, sizeof(fd)) == -1)
         fail_invalid_access(); // invalid memory access

      sys_close(fd);
      break;
    }

  /* unhandled case */
  unhandled:
    default:
      printf("[ERROR] Unrecognized or unimplemented system call: %d\n", syscall_number);
      sys_exit(-1);
      break;
  }
}

/* shuts down the entire operating system */
void sys_halt(void) {
  shutdown_power_off();
}

/* terminates the current user program or thread */
void sys_exit(int status) {
  printf("%s: exit(%d)\n", thread_current()->name, status);
  // The process exits.
  // wake up the parent process (if it was sleeping) using semaphore,
  // and pass the return code.
  struct process_control_block *pcb = thread_current()->pcb;
  ASSERT (pcb != NULL);

  pcb->exited = true;
  pcb->exitcode = status;
  sema_up (&pcb->sema_wait);

  thread_exit();
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr)); // this is inline assembly statement
  return result;
}

/*
  Reads a consecutive `bytes` bytes of user memory with the
  starting address `src` (uaddr), and writes to dst in the kernel space.
  Returns the number of bytes read, or -1 on page fault (invalid memory access)
 */
static int
memread_user (void *src, void *dst, size_t bytes)
{
  int32_t value;
  size_t i;
  for(i=0; i<bytes; i++) {
    value = get_user(src + i);
    if(value < 0) return -1; // invalid memory access (page fault), so return -1
    *(char*)(dst + i) = value & 0xff; // only reading a byte
  }
  return (int)bytes; // return number of bytes read
}

static struct file_desc*
find_file_desc(int fd)
{
  struct thread* curr = thread_current();
  struct file* output_file;
  int i;
  struct list_elem *e = list_begin(&curr->file_descriptors ) ;
  if (fd < 3) {
    return NULL;
  }

  for(i = 3; i < fd; i++){
    if (e == NULL)
      return NULL;
    e = list_next(e);
  }

  struct file_desc *file_des = list_entry(e, struct file_desc, elem);
  return file_des;

}

pid_t sys_exec (const char *cmd_line)
{
  _DEBUG_PRINTF ("[DEBUG] Exec : %s\n", cmdline);
  while(true); // placeholder for now

  // cmdline is an address to the character buffer, on user memory
  // so a validation check is required
  if (get_user((const uint8_t*) cmd_line) == -1) {
    // invalid memory access
    return fail_invalid_access();
  }

  tid_t child_tid = process_execute(cmd_line);
  return child_tid;
}

int sys_wait(pid_t pid) {
  _DEBUG_PRINTF ("[DEBUG] Wait : %d\n", pid);
  return process_wait(pid);
}

bool sys_write(int fd, const void *buffer, unsigned size, int* ret)
{
  // check if memory is valid
  if (get_user((const uint8_t*) buffer) == -1){
    // invalid
    thread_exit();
    return false;
  }

  if (fd == 1){ // stdout
    putbuf(buffer, size);
    *ret = size;
    return true;
  }
  else {
    printf("[Error] sys_write unimplemented\n");
  }
  return false;
}

static int fail_invalid_access(void) 
{
  sys_exit (-1);
  NOT_REACHED();
}

bool sys_create(const char* file, unsigned initial_size) // unsigned = unsigned integer
{
  bool return_code;
  // memory validation
  if (get_user((const uint8_t*) file) == -1) {
    return fail_invalid_access();
  }
  return_code = filesys_create(file, initial_size);
  return return_code;
}

bool sys_remove(const char* file) 
{
  bool return_code;
  // memory validation
  if (get_user((const uint8_t*) file) == -1) {
    return fail_invalid_access();
  }

  return_code = filesys_remove(file);
  return return_code;
}

int sys_open(const char* file) {
  struct file* file_opened;
  struct file_desc* fd = palloc_get_page(0);

  // memory validation
  if (get_user((const uint8_t*) file) == -1) {
    return fail_invalid_access();
  }

  file_opened = filesys_open(file);
  if (!file_opened) {
    return -1;
  }

  fd->file = file_opened; //file save

  struct list* fd_list = &thread_current()->file_descriptors;
  if (list_empty(fd_list)) {
    // 0, 1, 2 are reserved for stdin, stdout, stderr
    fd->id = 3;
  }
  else {
    fd->id = (list_entry(list_back(fd_list), struct file_desc, elem)->id) + 1;
  }
  list_push_back(fd_list, &(fd->elem));

  return fd->id;
}

int sys_filesize(int fd) {
  struct file_desc* file_d;

  // memory validation
  if (get_user((const uint8_t*) fd) == -1) {
    fail_invalid_access();
  }

  file_d = find_file_desc(fd);

  if(file_d == NULL) {
    return -1;
  }

  return file_length(file_d->file);
}

void sys_close(int fd) {
  struct file_desc* file_d = find_file_desc (fd);

  // memory validation
  if (get_user((const uint8_t*) fd) == -1) {
     fail_invalid_access();
  }

  if(file_d && file_d->file) {
    file_close(file_d->file);
    list_remove(&(file_d->elem));
    palloc_free_page(file_d);
  }
}
