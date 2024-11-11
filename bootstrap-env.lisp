(in-package #:bootstrap-env)

;; todo: use static array and memcpy
(defvar *dos-stub-bytes*
  '(#x0E #x1F #xBA #x0E #x00 #xB4 #x09 #xCD #x21 #xB8 #x01 #x4C #xCD #x21 #x54 
    #x68 #x69 #x73 #x20 #x70 #x72 #x6F #x67 #x72 #x61 #x6D #x20 #x63 #x61 #x6E
    #x6E #x6F #x74 #x20 #x62 #x65 #x20 #x72 #x75 #x6E #x20 #x69 #x6E #x20 #x44
    #x4F #x53 #x20 #x6D #x6F #x64 #x65 #x2E #x0D #x0D #x0A #x24 #x00 #x00 #x00
    #x00 #x00 #x00 #x00))

(defun calc-size-of-pe-fart (code-size)
  4096)

(defun fart-pe-file-to-mem (ptr code-ptr code-size entrypoint-offset)
  (let* ((alignment 1024))
    (labels ((round-to (x chunk)
               (* (ceiling x chunk) chunk)))
      (let* ((rounded-size-of-headers (round-to 500 alignment))
             (rounded-size-of-image (+ rounded-size-of-headers
                                       (round-to code-size alignment)))
             (rounded-size-of-code (round-to code-size alignment)))        
        ;;
        ;; dos header
        (setf (cffi:mem-ref ptr :uint16 0) #x5A4D)
        (setf (cffi:mem-ref ptr :uint16 60) 128) ;; start of nt headers    
        ;;
        ;; dos stub
        (loop
          for b in *dos-stub-bytes*
          for i from 64
          do (setf (cffi:mem-ref ptr :uint8 i) b))
        ;;
        ;; nt headers
        (setf (cffi:mem-ref ptr :uint32 128) #x00004550) ;; signature
        ;; image file header
        (setf (cffi:mem-ref ptr :uint16 132) #x8664) ;; arch is amd64
        (setf (cffi:mem-ref ptr :uint16 134) 1) ;; number of sections
        (setf (cffi:mem-ref ptr :uint32 136) 0) ;; todo: unix timestamp of when pe file created
        (setf (cffi:mem-ref ptr :uint32 140) 0) ;; deprecated - always zero
        (setf (cffi:mem-ref ptr :uint32 144) 0) ;; deprecated - always zero
        (setf (cffi:mem-ref ptr :uint16 148) 240)
        (setf (cffi:mem-ref ptr :uint16 150) ;; characteristics
              (logior #x0002                 ;; executable
                      #x0020)) ;; can access addresses >2gb
        ;; optional header
        (setf (cffi:mem-ref ptr :uint16 152) #x020B) ;; pe32+ (64bit pe format)
        (setf (cffi:mem-ref ptr :uint8 154) 0) ;; major linker version
        (setf (cffi:mem-ref ptr :uint8 155) 0) ;; minor linker version
        (setf (cffi:mem-ref ptr :uint32 156) code-size) ;; size of code
        (setf (cffi:mem-ref ptr :uint32 160) 0) ;; size of initialized data
        (setf (cffi:mem-ref ptr :uint32 164) 0) ;; size of uninitialized data
        (setf (cffi:mem-ref ptr :uint32 168) (+ 1024 entrypoint-offset)) ;; address of entrypoint
        (setf (cffi:mem-ref ptr :uint32 172) 1024)  ;; base of code
        (setf (cffi:mem-ref ptr :uint64 176) 65536) ;; image base
        (setf (cffi:mem-ref ptr :uint32 184) alignment) ;; section alignment - must be at least "file alignment"
        (setf (cffi:mem-ref ptr :uint32 188) alignment) ;; file alignment - should be Po2, 512-64k
        (setf (cffi:mem-ref ptr :uint16 192) 10) ;; major os version
        (setf (cffi:mem-ref ptr :uint16 194) 0)  ;; minor os version
        (setf (cffi:mem-ref ptr :uint16 196) 0)  ;; major image version
        (setf (cffi:mem-ref ptr :uint16 198) 0)  ;; minor image version
        (setf (cffi:mem-ref ptr :uint16 200) 0) ;; major subsystem version
        (setf (cffi:mem-ref ptr :uint16 202) 0) ;; minor subsystem version
        (setf (cffi:mem-ref ptr :uint32 204) 0) ;; reserved
        (setf (cffi:mem-ref ptr :uint32 208) rounded-size-of-image) ;; size of image
        (setf (cffi:mem-ref ptr :uint32 212) rounded-size-of-headers) ;; size of headers
        (setf (cffi:mem-ref ptr :uint32 216) 0)   ;; checksum
        (setf (cffi:mem-ref ptr :uint16 220) #x02) ;; subsystem - (gui windows)
        (setf (cffi:mem-ref ptr :uint16 222) ;; dll characteristics
              (logior ;;#x0020 ;; Image can handle a high entropy 64-bit virtual address space (64bit ASLR)
               ;;#x0040 ;; DLL can move (ASLR)
               ;;#x0100 ;; Image is NX compatible (memory execution protection)
               #x8000)) ;; TerminalServer aware
        (setf (cffi:mem-ref ptr :uint64 224) #x100000) ;; size of stack reserve
        (setf (cffi:mem-ref ptr :uint64 232) #x1000) ;; size of stack commit
        (setf (cffi:mem-ref ptr :uint64 240) #x100000) ;; size of heap reserve
        (setf (cffi:mem-ref ptr :uint64 248) #x1000) ;; size of heap commit
        (setf (cffi:mem-ref ptr :uint32 256) 0)    ;; reserved
        (setf (cffi:mem-ref ptr :uint32 260) 16) ;; Size of the DataDirectory array. 

        ;; Export Directory
        (setf (cffi:mem-ref ptr :uint32 264) 0)
        (setf (cffi:mem-ref ptr :uint32 268) 0)

        ;; Import Directory
        (setf (cffi:mem-ref ptr :uint32 272) 0)
        (setf (cffi:mem-ref ptr :uint32 276) 0)

        ;; Resource Directory
        (setf (cffi:mem-ref ptr :uint32 280) 0)
        (setf (cffi:mem-ref ptr :uint32 284) 0)

        ;; Exception Directory
        (setf (cffi:mem-ref ptr :uint32 288) 0)
        (setf (cffi:mem-ref ptr :uint32 292) 0)

        ;; Security Directory
        (setf (cffi:mem-ref ptr :uint32 296) 0)
        (setf (cffi:mem-ref ptr :uint32 300) 0)

        ;; Base Relocation Table
        (setf (cffi:mem-ref ptr :uint32 304) 0)
        (setf (cffi:mem-ref ptr :uint32 308) 0)

        ;; Debug Directory
        (setf (cffi:mem-ref ptr :uint32 312) 0)
        (setf (cffi:mem-ref ptr :uint32 316) 0)

        ;; Architecture Specific Data
        (setf (cffi:mem-ref ptr :uint32 320) 0)
        (setf (cffi:mem-ref ptr :uint32 324) 0)

        ;; RVA of GP
        (setf (cffi:mem-ref ptr :uint32 328) 0)
        (setf (cffi:mem-ref ptr :uint32 332) 0)

        ;; TLS Directory
        (setf (cffi:mem-ref ptr :uint32 336) 0)
        (setf (cffi:mem-ref ptr :uint32 340) 0)

        ;; Load Configuration Directory
        (setf (cffi:mem-ref ptr :uint32 344) 0)
        (setf (cffi:mem-ref ptr :uint32 348) 0)

        ;; Bound Import Directory in headers
        (setf (cffi:mem-ref ptr :uint32 352) 0)
        (setf (cffi:mem-ref ptr :uint32 356) 0)

        ;; Import Address Table
        (setf (cffi:mem-ref ptr :uint32 360) 0)
        (setf (cffi:mem-ref ptr :uint32 364) 0)

        ;; Delay Load Import Descriptors
        (setf (cffi:mem-ref ptr :uint32 368) 0)
        (setf (cffi:mem-ref ptr :uint32 372) 0)

        ;; COM Runtime descriptor  
        (setf (cffi:mem-ref ptr :uint32 376) 0)
        (setf (cffi:mem-ref ptr :uint32 380) 0)


        ;;
        ;; section headers
        ;; .text header
        (setf (cffi:mem-ref ptr :uint64 392) #x000000747865742E) ;; it's actually an 8 byte name string ".text"
        (setf (cffi:mem-ref ptr :uint32 400) 1024) ;; size of section once in memory
        (setf (cffi:mem-ref ptr :uint32 404) 1024) ;; address of the first byte of the section relative to the image base when loaded in memory
        (setf (cffi:mem-ref ptr :uint32 408) rounded-size-of-code) ;; size of the section on disk, it must be a multiple of IMAGE_OPTIONAL_HEADER.FileAlignment
        (setf (cffi:mem-ref ptr :uint32 412) 1024) ;; pointer to the first page of the section within the file, it must be a multiple of IMAGE_OPTIONAL_HEADER.FileAlignment
        (setf (cffi:mem-ref ptr :uint32 416) 0) ;; only used by dlls
        (setf (cffi:mem-ref ptr :uint32 420) 0) ;; deprecated
        (setf (cffi:mem-ref ptr :uint16 424) 0) ;; only used by dlls
        (setf (cffi:mem-ref ptr :uint16 426) 0) ;; deprecated
        (setf (cffi:mem-ref ptr :uint32 428) ;; characteristics
              (logior #x00000020 ;; code
                      #x20000000 ;; executable
                      #x40000000)) ;; readable

        ;;
        ;; .text section
        (loop
          for j below code-size
          for i from 1024
          do (setf (cffi:mem-ref ptr :uint8 i) (cffi:mem-ref code-ptr :uint8 j))))
      )))



(defun make-pe-file-in-mem ()
  (let* ((code '(#xCC #xC3))
         (code-size (length code))
         (code-arr (make-array
                    code-size
                    :initial-contents code
                    :element-type '(unsigned-byte 8)))
         (size (calc-size-of-pe-fart code-size))
         (ptr (cffi:foreign-alloc :uint8 :count size)))
    (loop
      for i below size
      do (setf (cffi:mem-ref ptr :uint8 i) 0))
    (cffi:with-pointer-to-vector-data (code-ptr code-arr)
      (fart-pe-file-to-mem ptr code-ptr code-size 0)
      (with-open-file (file "hello-lisp.exe"
                            :element-type '(unsigned-byte 8)
                            :direction :output
                            :if-exists :supersede
                            :if-does-not-exist :create)
        (loop
          for i below size
          do (write-byte (cffi:mem-ref ptr :uint8 i) file))))))


