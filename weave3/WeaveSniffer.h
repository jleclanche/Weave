namespace Weave {
	namespace Sniffer {
		const char* capture_device(void);
		const char* capture_file(void);
	
		bool set_capture_device(const char* device);
		bool set_capture_file(const char* filename);
		
		bool run(void);
		bool next(void);
		bool dispatch(int count);
	};
}
