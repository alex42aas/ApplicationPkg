
BASETOOLS_DIR = $(EDK_TOOLS_PATH)\Bin\Win32
#
# Build Macro
#
ASSEMBLY_CODE_FILE_LIST = $(MODULE_DIR)\smmstub.nas

TARGET_FILES = $(BUILD_DIR)\FV\smmstub.bin

INC = 
      
#OBJECTS = 

LIBS = 

COMMON_DEPS = 


all: $(TARGET_FILES)
          
#=============                
$(BUILD_DIR)\FV\smmstub.bin:$(MODULE_DIR)\smmstub.nas
	"$(NASM)" "$(MODULE_DIR)\smmstub.nas" -o $(BUILD_DIR)\FV\smmstub.bin
clean:
	if exist $(DEBUG_DIR) rmdir /s /q $(DEBUG_DIR)
	if exist $(OUTPUT_DIR) rmdir /s /q $(OUTPUT_DIR)


