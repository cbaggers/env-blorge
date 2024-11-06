;;;; bootstrap-env.lisp

(in-package #:bootstrap-env)

;; only need to set e-magic and e-lfanew
(define-io-structure image-dos-header
  ((e-magic uint16)            ;; Magic number (0x5A4D)
   (e-cblp uint16)             ;; Bytes on last page of file
   (e-cp uint16)               ;; Pages in file
   (e-crlc uint16)             ;; Relocations
   (e-cparhdr uint16)          ;; Size of header in paragraphs
   (e-minalloc uint16)         ;; Minimum extra paragraphs needed
   (e-maxalloc uint16)         ;; Maximum extra paragraphs needed
   (e-ss uint16)               ;; Initial (relative) SS value
   (e-sp uint16)               ;; Initial SP value
   (e-csum uint16)             ;; Checksum
   (e-ip uint16)               ;; Initial IP value
   (e-cs uint16)               ;; Initial (relative) CS value
   (e-lfarlc uint16)           ;; File address of relocation table
   (e-ovno uint16)             ;; Overlay number
   (e-res (vector uint16 4))   ;; Reserved words
   (e-oemid uint16)            ;; OEM identifier (for e-oeminfo)
   (e-oeminfo uint16)          ;; OEM information; e-oemid specific
   (e-res2 (vector uint16 10)) ;; Reserved words
   (e-lfanew uint64)))         ;; File address of new exe header


;; 0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68
;; 69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F 
;; 74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20 
;; 6D 6F 64 65 2E 0D 0D 0A 24 00 00 00 00 00 00 00

(defvar *dos-stub-bytes*
  '(#x0E #x1F #xBA #x0E #x00 #xB4 #x09 #xCD #x21 #xB8 #x01 #x4C #xCD #x21 #x54 #x68
    #x69 #x73 #x20 #x70 #x72 #x6F #x67 #x72 #x61 #x6D #x20 #x63 #x61 #x6E #x6E #x6F
    #x74 #x20 #x62 #x65 #x20 #x72 #x75 #x6E #x20 #x69 #x6E #x20 #x44 #x4F #x53 #x20
    #x6D #x6F #x64 #x65 #x2E #x0D #x0D #x0A #x24 #x00 #x00 #x00 #x00 #x00 #x00 #x00))

(define-io-structure image-dos-stub
  (bytes (vector uint8 64)))

;; I'm skipping the rich headers as they are optional (and rather undocumented)

;; typedef struct IMAGE_NT_HEADERS64 {
;;     DWORD Signature;
;;     IMAGE_FILE_HEADER FileHeader;
;;     IMAGE_OPTIONAL_HEADER64 OptionalHeader;
;; } 

(define-io-structure image-nt-headers-64
  (signature uint32) ;; (0x50450000)
  (file-header image-file-header)
  (optional-header image-optional-header-64))

;; typedef struct IMAGE_FILE_HEADER {
;;     WORD    Machine;
;;     WORD    NumberOfSections;
;;     DWORD   TimeDateStamp;
;;     DWORD   PointerToSymbolTable;
;;     DWORD   NumberOfSymbols;
;;     WORD    SizeOfOptionalHeader;
;;     WORD    Characteristics;
;; }

(define-io-structure image-file-header
  ((machine uint16)
   (number-of-sections uint16)
   (time-date-stamp uint32)
   (pointer-to-symbol-table uint32)
   (number-of-symbols uint32)
   (size-of-optional-header uint16)
   (characteristics uint16)))

;; typedef struct _IMAGE_OPTIONAL_HEADER64 {
;;     WORD        Magic;
;;     BYTE        MajorLinkerVersion;
;;     BYTE        MinorLinkerVersion;
;;     DWORD       SizeOfCode;
;;     DWORD       SizeOfInitializedData;
;;     DWORD       SizeOfUninitializedData;
;;     DWORD       AddressOfEntryPoint;
;;     DWORD       BaseOfCode;
;;     ULONGLONG   ImageBase;
;;     DWORD       SectionAlignment;
;;     DWORD       FileAlignment;
;;     WORD        MajorOperatingSystemVersion;
;;     WORD        MinorOperatingSystemVersion;
;;     WORD        MajorImageVersion;
;;     WORD        MinorImageVersion;
;;     WORD        MajorSubsystemVersion;
;;     WORD        MinorSubsystemVersion;
;;     DWORD       Win32VersionValue;
;;     DWORD       SizeOfImage;
;;     DWORD       SizeOfHeaders;
;;     DWORD       CheckSum;
;;     WORD        Subsystem;
;;     WORD        DllCharacteristics;
;;     ULONGLONG   SizeOfStackReserve;
;;     ULONGLONG   SizeOfStackCommit;
;;     ULONGLONG   SizeOfHeapReserve;
;;     ULONGLONG   SizeOfHeapCommit;
;;     DWORD       LoaderFlags;
;;     DWORD       NumberOfRvaAndSizes;
;;     IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
;; } IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
(define-io-structure image-optional-header-64
  (magic uint16) ;; (0x20B)
  (major-linker-version uint8)
  (minor-linker-version uint8)
  (size-of-code uint32)
  (size-of-initialized-data uint32)
  (size-of-uninitialized-data uint32)
  (address-of-entry-point uint32)
  (base-of-code uint32)
  (image-base uint64)
  (section-alignment uint32)
  (file-attachment uint32)
  (major-operating-system-version uint16)
  (minor-operating-system-version uint16)
  (major-image-version uint16)
  (minor-image-version uint16)
  (major-subsystem-version uint16)
  (minor-subsystem-version uint16)
  (win32-version-value uint32)
  (size-of-image uint32)
  (size-of-headers uint32)
  (check-sum uint32)
  (subsystem uint16)
  (dll-characteristics uint16)
  (size-of-stack-reserve uint64)
  (size-of-stack-commit uint64)
  (size-of-heap-reserve uint64)
  (size-of-heap-commit uint64)
  (loader-flags uint32)
  (number-of-rva-and-sizes uint32)
  (data-directory (vector image-data-directory image_numberof_directory_entries)))
