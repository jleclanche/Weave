#include <Python.h>
#include "structmember.h"

#ifdef WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <weave.h>
#include <cstdio>
#include <typeinfo>

typedef struct {
	PyObject_HEAD
	PyObject* message_handler;
} PyWeave_SnifferObject;

static PyWeave_SnifferObject* sniffer;

static PyTypeObject PyWeave_SnifferType = {
	PyObject_HEAD_INIT(NULL)
	0,
	"weave.Sniffer",
	sizeof(PyWeave_SnifferObject)
};

static PyObject* PyWeave_Sniffer_get_file(PyWeave_SnifferObject* self, void* closure)
{
	const char* file = Weave::Sniffer::capture_file();
	
	if(file)
		return PyString_FromString(file);
	else
		Py_RETURN_NONE;
}

static int PyWeave_Sniffer_set_device(PyWeave_SnifferObject* self, PyObject* value, void* closure)
{
	const char* newDevice = PyString_AsString(value);
	if(newDevice) {
		if(Weave::Sniffer::set_capture_device(newDevice))
			return 0;
		else {
			PyErr_SetString(PyExc_RuntimeError, "Could not set new capture device");
			return -1;
		}
	} else {
		return -1;
	}
}

static PyObject* PyWeave_Sniffer_get_device(PyWeave_SnifferObject* self, void* closure)
{
	const char* device = Weave::Sniffer::capture_device();
	
	if(device)
		return PyString_FromString(device);
	else
		Py_RETURN_NONE;
}

static int PyWeave_Sniffer_set_file(PyWeave_SnifferObject* self, PyObject* value, void* closure)
{
	const char* newFile = PyString_AsString(value);
	if(newFile) {
		if(Weave::Sniffer::set_capture_file(newFile))
			return 0;
		else {
			PyErr_SetString(PyExc_RuntimeError, "Could not set new capture file");
			return -1;
		}
	} else {
		return -1;
	}
}

static PyGetSetDef PyWeave_SnifferGetSets[] = {
	{ "file", (getter)PyWeave_Sniffer_get_file, (setter)PyWeave_Sniffer_set_file, NULL, NULL },
	{ "device", (getter)PyWeave_Sniffer_get_device, (setter)PyWeave_Sniffer_set_device, NULL, NULL },
	{ 0 }
};

static PyMemberDef PyWeave_SnifferMembers[] = {
	{ "message_handler", T_OBJECT, offsetof(PyWeave_SnifferObject, message_handler), 0, NULL },
	{ 0 }
};

static PyObject* PyWeave_Sniffer_dispatch(PyWeave_SnifferObject* self, PyObject* pargs, PyObject* kwargs)
{
	long int count;
	
	if(PyArg_ParseTuple(pargs, "l", &count))
	{
		return PyInt_FromLong(Weave::Sniffer::dispatch(count));
	}
	
	return NULL;
}

static PyObject* PyWeave_Sniffer_run(PyWeave_SnifferObject* self)
{
	bool capturingFromFile = (Weave::Sniffer::capture_file() != NULL);
	
	for(;;)
	{
		if(!Weave::Sniffer::next() && capturingFromFile)
			break;
		
		if(PyErr_CheckSignals() < 0 || PyErr_Occurred())
			return NULL;
	}
	
	Py_RETURN_NONE;
}

static PyObject* PyWeave_Sniffer_next(PyWeave_SnifferObject* self)
{
	if(Weave::Sniffer::next())
		Py_RETURN_TRUE;
	else 
		Py_RETURN_FALSE;
}


static PyMethodDef PyWeave_SnifferMethods[] = {
	{ "dispatch", (PyCFunction)PyWeave_Sniffer_dispatch, METH_VARARGS, NULL },
	{ "run", (PyCFunction)PyWeave_Sniffer_run, METH_NOARGS, NULL },
	{ "next", (PyCFunction)PyWeave_Sniffer_next, METH_NOARGS, NULL },
	{ NULL }
};

typedef struct {
	PyObject_HEAD
	unsigned long opcode;
	char* data;
	Py_ssize_t data_length;
} PyWeave_MessageObject;

static PyTypeObject PyWeave_MessageType = {
	PyObject_HEAD_INIT(NULL)
	0,
	"weave.Message",
	sizeof(PyWeave_MessageObject)
};

static PyTypeObject PyWeave_ClientMessageType = {
	PyObject_HEAD_INIT(NULL)
	0,
	"weave.ClientMessage",
	sizeof(PyWeave_MessageObject)
};

static PyTypeObject PyWeave_ServerMessageType = {
	PyObject_HEAD_INIT(NULL)
	0,
	"weave.ServerMessage",
	sizeof(PyWeave_MessageObject)
};

static PyObject* PyWeave_Message_get_data(PyWeave_MessageObject* self, void* closure)
{
	return PyString_FromStringAndSize(self->data, self->data_length);
}

static PyGetSetDef PyWeave_MessageGetSets[] = {
	{ "data", (getter)PyWeave_Message_get_data, NULL, NULL, NULL },
	{ NULL }
};

static PyMemberDef PyWeave_MessageMembers[] = {
	{ "opcode", T_ULONG, offsetof(PyWeave_MessageObject, opcode), READONLY, NULL },
	{ "data_length", T_PYSSIZET, offsetof(PyWeave_MessageObject, data_length), READONLY, NULL },
	{ NULL }
};

void PyWeave_message_callback(const Weave::GameConnection& connection, const Weave::GameConnection::Peer& peer, const Weave::GameConnection::Peer::Header& header, const unsigned char* payload)
{
	if(sniffer->message_handler && sniffer->message_handler != Py_None)
	{
		PyTypeObject* msgtype = NULL;
		
		if(typeid(peer) == typeid(Weave::GameConnection::Client))
			msgtype = &PyWeave_ClientMessageType;
		else if(typeid(peer) == typeid(Weave::GameConnection::Server))
			msgtype = &PyWeave_ServerMessageType;
		else
			return;
		
		PyWeave_MessageObject* message = PyObject_New(PyWeave_MessageObject, msgtype);
		if(!message)
			return;
		
		message->opcode = (unsigned long)header.opcode();
		
		if(payload) {
			message->data_length = header.payloadSize();
			message->data = (char*)PyMem_Malloc(message->data_length);
			if(message->data)
				memcpy(message->data, payload, message->data_length);
		} else {
			message->data_length = 0;
			message->data = NULL;
		}
		
		PyObject* result = PyObject_CallFunctionObjArgs(sniffer->message_handler, message, NULL);
		if(result)
			Py_DECREF(result);
	}
}

PyObject* PyWeave_Message_tp_repr(PyWeave_MessageObject* self)
{
	const char* opcode_name = Weave::Opcodes::to_string((Weave::Opcodes::Opcode)self->opcode);
	
	if(self->data_length)
	{
		if(opcode_name)
			return PyString_FromFormat("<%s (%zd bytes)>", opcode_name, self->data_length);
		else
			return PyString_FromFormat("<UMSG_UNKNOWN_%lu (%zd bytes)>", self->opcode, self->data_length);
	} else {
		if(opcode_name)
			return PyString_FromFormat("<%s>", opcode_name);
		else
			return PyString_FromFormat("<UMSG_UNKNOWN_%lu>", self->opcode);
	}
}

void PyWeave_Message_tp_dealloc(PyWeave_MessageObject* self)
{
	if(self->data)
		PyMem_Free(self->data);
	
	self->ob_type->tp_free(self);
}

typedef struct {
	PyObject_HEAD
	Weave::Log::SessionInfo info;
	PyObject* account;
} PyWeave_SessionInfoObject;

static PyTypeObject PyWeave_SessionInfoType = {
	PyObject_HEAD_INIT(NULL)
	0,
	"weave.SessionInfo",
	sizeof(PyWeave_SessionInfoObject)
};

static PyMemberDef PyWeave_SessionInfoMembers[] = {
	{ "account", T_OBJECT, offsetof(PyWeave_SessionInfoObject, account), READONLY, NULL },
	{ NULL }
};

PyObject* PyWeave_SessionInfo_get_game(PyWeave_SessionInfoObject* self)
{
	char game[sizeof(self->info.game)+1] = { 0 };
	strncpy(game, self->info.game, sizeof(self->info.game));
	return PyString_FromString(game);
}

PyObject* PyWeave_SessionInfo_get_build(PyWeave_SessionInfoObject* self)
{
	return PyInt_FromLong(self->info.build[0] | (self->info.build[1] << 8));
}

PyObject* PyWeave_SessionInfo_get_client(PyWeave_SessionInfoObject* self)
{
	unsigned long addr_unpacked = self->info.client_ip[0] | (self->info.client_ip[1] << 8) | (self->info.client_ip[2] << 16) | (self->info.client_ip[3] << 24);
	struct in_addr* addr = (struct in_addr*)(&addr_unpacked);
	char* addr_string = inet_ntoa(*addr);
	unsigned short port_unpacked = self->info.client_port[0] | (self->info.client_port[1] << 8);
	
	return PyTuple_Pack(2, PyString_FromString(addr_string), PyInt_FromLong(port_unpacked));
}

PyObject* PyWeave_SessionInfo_get_server(PyWeave_SessionInfoObject* self)
{
	unsigned long addr_unpacked = self->info.server_ip[0] | (self->info.server_ip[1] << 8) | (self->info.server_ip[2] << 16) | (self->info.server_ip[3] << 24);
	struct in_addr* addr = (struct in_addr*)(&addr_unpacked);
	char* addr_string = inet_ntoa(*addr);
	unsigned short port_unpacked = self->info.server_port[0] | (self->info.server_port[1] << 8);
	
	return PyTuple_Pack(2, PyString_FromString(addr_string), PyInt_FromLong(port_unpacked));
}

PyObject* PyWeave_SessionInfo_get_locale(PyWeave_SessionInfoObject* self)
{
	char locale[sizeof(self->info.locale)+1] = { 0 };
	strncpy(locale, self->info.locale, sizeof(self->info.locale));
	return PyString_FromString(locale);
}

PyObject* PyWeave_SessionInfo_get_version(PyWeave_SessionInfoObject* self)
{
	PyObject* major = PyInt_FromLong(self->info.major);
	PyObject* minor = PyInt_FromLong(self->info.minor);
	PyObject* revision = PyInt_FromLong(self->info.revision);
	PyObject* build = PyInt_FromLong(self->info.build[0] | (self->info.build[1] << 8));
	
	return PyTuple_Pack(4, major, minor, revision, build);
}

static PyGetSetDef PyWeave_SessionInfoGetSets[] = {
	{ "game", (getter)PyWeave_SessionInfo_get_game, (setter)NULL, NULL, NULL },
	{ "build", (getter)PyWeave_SessionInfo_get_build, (setter)NULL, NULL, NULL },
	{ "client", (getter)PyWeave_SessionInfo_get_client, (setter)NULL, NULL, NULL },
	{ "locale", (getter)PyWeave_SessionInfo_get_locale, (setter)NULL, NULL, NULL },
	{ "server", (getter)PyWeave_SessionInfo_get_server, (setter)NULL, NULL, NULL },
	{ "version", (getter)PyWeave_SessionInfo_get_version, (setter)NULL, NULL, NULL },
	{ NULL }
};

void PyWeave_SessionInfo_tp_dealloc(PyWeave_SessionInfoObject* self)
{
	Py_XDECREF(self->account);
	self->ob_type->tp_free(self);
}

typedef struct {
	PyObject_HEAD
	PyObject* logfile;
} PyWeave_LogObject;

static PyTypeObject PyWeave_LogType = {
	PyObject_HEAD_INIT(NULL)
	0,
	"weave.Log",
	sizeof(PyWeave_LogObject)
};

typedef struct {
	PyObject_HEAD
	PyWeave_LogObject* log;
	off_t offset;
} PyWeave_LogIterObject;

static PyTypeObject PyWeave_LogIterType = {
	PyObject_HEAD_INIT(NULL)
	0,
	"weave.LogIter",
	sizeof(PyWeave_LogIterObject)
};

PyWeave_LogIterObject* PyWeave_LogIter_tp_iter(PyWeave_LogIterObject* self)
{
	return self;
}

PyObject* PyWeave_LogIter_tp_iternext(PyWeave_LogIterObject* self)
{
	FILE* logfile = PyFile_AsFile(self->log->logfile);
	
	if(logfile && !fseek(logfile, sizeof(Weave::Log::Header) + self->offset, SEEK_SET))
	{
		uint8_t packed_typecode[2];
		if(fread(packed_typecode, sizeof(packed_typecode), 1, logfile) != 1)
		{
			self->offset = 0;
			return NULL;
		}
		
		Weave::Log::TypeCode typecode = (Weave::Log::TypeCode)(packed_typecode[0] | (packed_typecode[1] << 8));
		
		uint8_t packed_size[4];
		if(fread(packed_size, sizeof(packed_size), 1, logfile) != 1)
		{
			self->offset = 0;
			return NULL;
		}
		
		size_t size = packed_size[0] | (packed_size[1] << 8) | (packed_size[2] << 16) | (packed_size[3] << 24);
		self->offset += size + 6;
		
		if(typecode == Weave::Log::TC_CLIENT_MESSAGE || typecode == Weave::Log::TC_SERVER_MESSAGE)
		{
			PyWeave_MessageObject* msg = NULL;
			if(typecode == Weave::Log::TC_CLIENT_MESSAGE)
				msg = PyObject_New(PyWeave_MessageObject, &PyWeave_ClientMessageType);
			else if(typecode == Weave::Log::TC_SERVER_MESSAGE)
				msg = PyObject_New(PyWeave_MessageObject, &PyWeave_ServerMessageType);
			
			if(!msg)
				return NULL;
			
			Weave::Log::Message msg_header;
			if(fread(&msg_header, sizeof(msg_header), 1, logfile) != 1)
			{
				self->offset = 0;
				
				Py_DECREF(msg);
				return NULL;
			}
			
			msg->opcode = msg_header.opcode[0] | (msg_header.opcode[1] << 8) | (msg_header.opcode[2] << 16) | (msg_header.opcode[3] << 24);
			msg->data_length = size - sizeof(msg_header);
			if(msg->data_length)
			{
				msg->data = (char*)PyMem_Malloc(msg->data_length);
				fread(msg->data, msg->data_length, 1, logfile);
			} else {
				msg->data = NULL;
			}
			
			return (PyObject*)msg;
		} else if(typecode == Weave::Log::TC_SESSION_INFO) {
			PyWeave_SessionInfoObject* info_obj = PyObject_New(PyWeave_SessionInfoObject, &PyWeave_SessionInfoType);
			if(!info_obj)
				return NULL;
			
			if(fread(&(info_obj->info), sizeof(info_obj->info), 1, logfile) != 1)
			{
				self->offset = 0;
				
				Py_DECREF(info_obj);
				return NULL;
			}
			
			size_t account_length = size - sizeof(info_obj->info);
			if(account_length)
			{
				char* buffer = new char[account_length];
				if(fread(buffer, account_length, 1, logfile) != 1)
				{
					self->offset = 0;
					Py_DECREF(info_obj);
					delete buffer;
					return NULL;
				}
				
				info_obj->account = PyUnicode_DecodeUTF8(buffer, account_length - 1, "strict");
				if(!info_obj->account)
				{
					self->offset = 0;
					Py_DECREF(info_obj);
					delete buffer;
					return NULL;
				}
				
				delete buffer;
			} else {
				info_obj->account = NULL;
			}
			
			return (PyObject*)info_obj;
		}
		
		Py_RETURN_NONE;
	} else {
		self->offset = 0;
	}

	return NULL;
}

void PyWeave_LogIter_tp_dealloc(PyWeave_LogIterObject* self)
{
	Py_DECREF(self->log);
	self->ob_type->tp_free(self);
}

int PyWeave_Log_tp_init(PyWeave_LogObject* self, PyObject* args, PyObject* kwargs)
{
	PyObject* py_logfile;
	self->logfile = NULL;
	
	if(PyArg_ParseTuple(args, "O!", &PyFile_Type, &py_logfile))
	{
		FILE* logfile = PyFile_AsFile(py_logfile);
		if(!logfile)
			return -1;
		
		if(fseek(logfile, 0, SEEK_SET))
		{
			PyErr_SetString(PyExc_IOError, "Could not seek to beginning of log file");
			return -1;
		}
		
		char ident[sizeof(Weave::Log::ident)];
		if(fread(ident, sizeof(ident), 1, logfile) != 1)
		{
			PyErr_SetString(PyExc_IOError, "Could not read log file identifier");
			return -1;
		}
		
		if(strncmp(ident, Weave::Log::ident, sizeof(Weave::Log::ident)))
		{
			PyErr_SetString(PyExc_ValueError, "Invalid log file identifier");
			return -1;
		}
		
		uint8_t packed_version[4];
		if(fread(packed_version, sizeof(packed_version), 1, logfile) != 1)
		{
			PyErr_SetString(PyExc_IOError, "Could not read log file version");
			return -1;
		}
		
		uint32_t version = packed_version[0] | (packed_version[1] << 8) | (packed_version[2] << 16) | (packed_version[3] << 24);
		
		if(version > Weave::Log::version)
		{
			PyErr_SetString(PyExc_ValueError, "Log file version too high. Please upgrade.");
			return -1;
		}
		
		if(fseek(logfile, sizeof(Weave::Log::Header), SEEK_SET))
		{
			PyErr_SetString(PyExc_IOError, "Could not seek to end of log file header");
			return -1;
		}
		
		self->logfile = py_logfile;
		Py_INCREF(py_logfile);
		return 0;
	}
	
	return -1;
}

PyWeave_LogIterObject* PyWeave_Log_tp_iter(PyWeave_LogObject* self)
{
	PyWeave_LogIterObject* iter = PyObject_New(PyWeave_LogIterObject, &PyWeave_LogIterType);
	iter->offset = 0;
	iter->log = self;
	Py_INCREF(self);
	return iter;
}

PyMODINIT_FUNC
initweave(void)
{
	PyObject* module = Py_InitModule("weave", NULL);
	if(!module)
		return;
	
	PyWeave_SnifferType.tp_flags = Py_TPFLAGS_DEFAULT;
	PyWeave_SnifferType.tp_getset = PyWeave_SnifferGetSets;
	PyWeave_SnifferType.tp_methods = PyWeave_SnifferMethods;
	PyWeave_SnifferType.tp_members = PyWeave_SnifferMembers;

	if(PyType_Ready(&PyWeave_SnifferType) < 0)
		return;
	
	PyWeave_MessageType.tp_flags = Py_TPFLAGS_DEFAULT;
	PyWeave_MessageType.tp_getset = PyWeave_MessageGetSets;
	PyWeave_MessageType.tp_members = PyWeave_MessageMembers;
	PyWeave_MessageType.tp_repr = (reprfunc)PyWeave_Message_tp_repr;
	
	if(PyType_Ready(&PyWeave_MessageType) < 0)
		return;
	if(PyModule_AddObject(module, "Message", (PyObject*)&PyWeave_MessageType) < 0)
		return;
	
	PyWeave_ClientMessageType.tp_flags = Py_TPFLAGS_DEFAULT;
	PyWeave_ClientMessageType.tp_base = &PyWeave_MessageType;
	
	if(PyType_Ready(&PyWeave_ClientMessageType) < 0)
		return;
	if(PyModule_AddObject(module, "ClientMessage", (PyObject*)&PyWeave_ClientMessageType) < 0)
		return;
	
	PyWeave_ServerMessageType.tp_flags = Py_TPFLAGS_DEFAULT;
	PyWeave_ServerMessageType.tp_base = &PyWeave_MessageType;
	
	if(PyType_Ready(&PyWeave_ServerMessageType) < 0)
		return;
	if(PyModule_AddObject(module, "ServerMessage", (PyObject*)&PyWeave_ServerMessageType) < 0)
		return;
	
	PyWeave_SessionInfoType.tp_flags = Py_TPFLAGS_DEFAULT;
	PyWeave_SessionInfoType.tp_dealloc = (destructor)PyWeave_SessionInfo_tp_dealloc;
	PyWeave_SessionInfoType.tp_members = PyWeave_SessionInfoMembers;
	PyWeave_SessionInfoType.tp_getset = PyWeave_SessionInfoGetSets;
	if(PyType_Ready(&PyWeave_SessionInfoType) < 0)
		return;
	if(PyModule_AddObject(module, "SessionInfo", (PyObject*)&PyWeave_SessionInfoType) < 0)
		return;
	
	PyWeave_LogIterType.tp_flags = Py_TPFLAGS_DEFAULT;
	PyWeave_LogIterType.tp_dealloc = (destructor)PyWeave_LogIter_tp_dealloc;
	PyWeave_LogIterType.tp_iter = (getiterfunc)PyWeave_LogIter_tp_iter;
	PyWeave_LogIterType.tp_iternext = (iternextfunc)PyWeave_LogIter_tp_iternext;
	
	if(PyType_Ready(&PyWeave_LogIterType) < 0)
		return;
	if(PyModule_AddObject(module, "LogIter", (PyObject*)&PyWeave_LogIterType) < 0)
		return;
	
	PyWeave_LogType.tp_flags = Py_TPFLAGS_DEFAULT;
	PyWeave_LogType.tp_init = (initproc)PyWeave_Log_tp_init;
	PyWeave_LogType.tp_new = PyType_GenericNew;
	PyWeave_LogType.tp_iter = (getiterfunc)PyWeave_Log_tp_iter;
	
	if(PyType_Ready(&PyWeave_LogType) < 0)
		return;
	if(PyModule_AddObject(module, "Log", (PyObject*)&PyWeave_LogType) < 0)
		return;
	
	sniffer = PyObject_New(PyWeave_SnifferObject, &PyWeave_SnifferType);
	sniffer->message_handler = NULL;
	
	if(!sniffer || PyModule_AddObject(module, "Sniffer", (PyObject*)sniffer) < 0)
		return;
	
	Py_INCREF(&PyWeave_SnifferType);
	
	Weave::GameConnection::message_callback = PyWeave_message_callback;
	
	PyObject* opcode_dict = PyDict_New();
	if(!opcode_dict)
		return;
	
	unsigned int opcode_index;
	for(opcode_index = 0; opcode_index < Weave::Opcodes::count; opcode_index++)
	{
		if(PyModule_AddIntConstant(module, Weave::Opcodes::opcodes[opcode_index].name, (long)Weave::Opcodes::opcodes[opcode_index].opcode) < 0)
			return;
		
		PyObject* opcode_number = PyInt_FromLong((long)Weave::Opcodes::opcodes[opcode_index].opcode);
		PyObject* opcode_string = PyString_FromString(Weave::Opcodes::opcodes[opcode_index].name);
		
		PyDict_SetItem(opcode_dict, opcode_number, opcode_string);
	}
	
	PyObject* opcode_dict_proxy = PyDictProxy_New(opcode_dict);
	PyModule_AddObject(module, "opcodes", opcode_dict_proxy);
}
