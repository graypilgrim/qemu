/*
 * SpiceWire module for ARM architecture.
 *
 * Copyright (c) 2017 Lukasz Wlazly.
 * Written as a part of BSc thesis
 *
 * This code is licensed under the GPL.
 */

#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "qemu/error-report.h"
#include "io/channel.h"
#include "io/channel-file.h"
#include "io/channel-socket.h"
#include "qapi/error.h"
#include "sysemu/sysemu.h"

#include <time.h>
#include "qemu/thread.h"

#define SPW_TRANSMIT_DESC_HEADER_MASK 0x000000FF
#define SPW_TRANSMIT_MIN_HEADER_LEN 15
#define SPW_TRANSMIT_DESC_NONCRC_MASK 0x00000F00
#define SPW_TRANSMIT_DESC_ENABLE_MASK 0x00001000
#define SPW_TRANSMIT_DESC_WRAP_MASK 0x00002000
#define SPW_TRANSMIT_DESC_INTERRUPT_ENABLE_MASK 0x00004000
#define SPW_TRANSMIT_DESC_LINK_ERROR_MASK 0x00008000
#define SPW_TRANSMIT_DESC_APPEND_HEADER_CRC_MASK 0x00010000
#define SPW_TRANSMIT_DESC_APPEND_DATA_CRC_MASK 0x00020000
#define SPW_TRANSMIT_DESC_CRC_TYPE_MASK 0x000C0000
#define SPW_TRANSMIT_DESC_DATA_LEN_MASK 0x00FFFFFF

#define SPW_FIFO_LENGTH 64
#define RMAP_MIN_PACKAGE_LEN (SPW_TRANSMIT_MIN_HEADER_LEN + 1)
#define RMAP_DATA_CRC_LEN 1
#define RMAP_PROTOCOL_IDENTIFIER 0x01
#define RMAP_package_TYPE_COMMAND 0x40
#define RMAP_package_WRITE_COMMAND 0x20
#define RMAP_EOP 0xf0
#define RMAP_MAX_PACKAGE_LEN 16777215
#define RMAP_TRANSACTION_ID_MS_ 5
#define RMAP_TRANSACTION_ID_LS_ 6

#define TYPE_SPACEWIRE "spacewire"
#define SPACEWIRE(obj) OBJECT_CHECK(SpaceWireState, (obj), TYPE_SPACEWIRE)

typedef enum _RMAP_Socket_Read_Status {
		RMAP_SOCKET_READ_STATUS_START,
		RMAP_SOCKET_READ_STATUS_DATA,
		RMAP_SOCKET_READ_STATUS_PARTIAL_HEADER,
		RMAP_SOCKET_READ_STATUS_PARTIAL_DATA,
		RMAP_SOCKET_READ_STATUS_READ_EOP,
		RMAP_SOCKET_READ_STATUS_COMPLETED
	} RMAP_Socket_Read_Status;

static QIOChannel *io_channel = NULL;
static QemuThread main_loop_thread;
static QemuThread transmit_loop_thread;

typedef struct SpaceWireState {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    int level[2];
    qemu_irq irq;
} SpaceWireState;

typedef struct _SpWRegisters {
    uint32_t trnsDescIndex;
    uint32_t rcvDescIndex;
} SpWRegisters;
SpWRegisters registers;

#define DESCRIPTOR_TABLE_LEN 64

#define RCV_DESCRIPTOR_WRAP_MASK (0x1 << 26)
#define RCV_DESCRIPTOR_ENABLE_MASK (0x1 << 25)

typedef struct {
    uint32_t word0;
    uint32_t word1;
} SpWReceiveDescriptor;
static SpWReceiveDescriptor receiveDescTable[DESCRIPTOR_TABLE_LEN];

static uint8_t RMAPHeader[256];
static uint32_t counter = 0xFFFF;

QIOChannelFile *file;

#define TRNS_DESCRIPTOR_WRAP_MASK (0x1 << 13)
#define TRNS_DESCRIPTOR_ENABLE_MASK (0x1 << 12)

typedef struct {
    uint32_t word0;
    uint32_t word1;
    uint32_t word2;
    uint32_t word3;
} SpWTransmitDescriptor;
static SpWTransmitDescriptor transmitDescTable[DESCRIPTOR_TABLE_LEN];

unsigned char RMAP_CRCTable[] = {
  0x00, 0x91, 0xe3, 0x72, 0x07, 0x96, 0xe4, 0x75,
  0x0e, 0x9f, 0xed, 0x7c, 0x09, 0x98, 0xea, 0x7b,
  0x1c, 0x8d, 0xff, 0x6e, 0x1b, 0x8a, 0xf8, 0x69,
  0x12, 0x83, 0xf1, 0x60, 0x15, 0x84, 0xf6, 0x67,
  0x38, 0xa9, 0xdb, 0x4a, 0x3f, 0xae, 0xdc, 0x4d,
  0x36, 0xa7, 0xd5, 0x44, 0x31, 0xa0, 0xd2, 0x43,
  0x24, 0xb5, 0xc7, 0x56, 0x23, 0xb2, 0xc0, 0x51,
  0x2a, 0xbb, 0xc9, 0x58, 0x2d, 0xbc, 0xce, 0x5f,
  0x70, 0xe1, 0x93, 0x02, 0x77, 0xe6, 0x94, 0x05,
  0x7e, 0xef, 0x9d, 0x0c, 0x79, 0xe8, 0x9a, 0x0b,
  0x6c, 0xfd, 0x8f, 0x1e, 0x6b, 0xfa, 0x88, 0x19,
  0x62, 0xf3, 0x81, 0x10, 0x65, 0xf4, 0x86, 0x17,
  0x48, 0xd9, 0xab, 0x3a, 0x4f, 0xde, 0xac, 0x3d,
  0x46, 0xd7, 0xa5, 0x34, 0x41, 0xd0, 0xa2, 0x33,
  0x54, 0xc5, 0xb7, 0x26, 0x53, 0xc2, 0xb0, 0x21,
  0x5a, 0xcb, 0xb9, 0x28, 0x5d, 0xcc, 0xbe, 0x2f,
  0xe0, 0x71, 0x03, 0x92, 0xe7, 0x76, 0x04, 0x95,
  0xee, 0x7f, 0x0d, 0x9c, 0xe9, 0x78, 0x0a, 0x9b,
  0xfc, 0x6d, 0x1f, 0x8e, 0xfb, 0x6a, 0x18, 0x89,
  0xf2, 0x63, 0x11, 0x80, 0xf5, 0x64, 0x16, 0x87,
  0xd8, 0x49, 0x3b, 0xaa, 0xdf, 0x4e, 0x3c, 0xad,
  0xd6, 0x47, 0x35, 0xa4, 0xd1, 0x40, 0x32, 0xa3,
  0xc4, 0x55, 0x27, 0xb6, 0xc3, 0x52, 0x20, 0xb1,
  0xca, 0x5b, 0x29, 0xb8, 0xcd, 0x5c, 0x2e, 0xbf,
  0x90, 0x01, 0x73, 0xe2, 0x97, 0x06, 0x74, 0xe5,
  0x9e, 0x0f, 0x7d, 0xec, 0x99, 0x08, 0x7a, 0xeb,
  0x8c, 0x1d, 0x6f, 0xfe, 0x8b, 0x1a, 0x68, 0xf9,
  0x82, 0x13, 0x61, 0xf0, 0x85, 0x14, 0x66, 0xf7,
  0xa8, 0x39, 0x4b, 0xda, 0xaf, 0x3e, 0x4c, 0xdd,
  0xa6, 0x37, 0x45, 0xd4, 0xa1, 0x30, 0x42, 0xd3,
  0xb4, 0x25, 0x57, 0xc6, 0xb3, 0x22, 0x50, 0xc1,
  0xba, 0x2b, 0x59, 0xc8, 0xbd, 0x2c, 0x5e, 0xcf,
};

unsigned char calculate_crc(unsigned char *data, unsigned int len)
{
  unsigned char crc = 0;
  for (unsigned int i = 0; i < len; ++i) {
    crc = RMAP_CRCTable[crc ^ *data];
    data++;
  }

  return crc;
}

unsigned get_rmap_data_len(uint8_t* package)
{
  unsigned res = 0;

	res += (package[12] << 16);
	res += (package[13] << 8);
	res += package[14];

	return res;
}

unsigned get_package_id(uint8_t* package)
{
	unsigned res = 0;

	res += (package[RMAP_TRANSACTION_ID_MS_] << 8);
	res += package[RMAP_TRANSACTION_ID_LS_];

	return res;
}

void log_package(uint8_t *package, bool sent)
{
	char res[2048] = {0};

	struct timespec time1;
  clock_gettime(CLOCK_MONOTONIC, &time1);
	sprintf(res, "%u\t%s\t%u\t%s\t%ld:%ld\n", get_package_id(package), (sent ? "S" : "R"), get_rmap_data_len(package), "C", time1.tv_sec, time1.tv_nsec);
	qio_channel_write(QIO_CHANNEL(file), res, strlen(res), &error_abort);
}

int create_rmap_package(SpWTransmitDescriptor *descriptor, unsigned char** package)
{
  unsigned header_len = descriptor->word0 & SPW_TRANSMIT_DESC_HEADER_MASK;
  if (header_len < SPW_TRANSMIT_MIN_HEADER_LEN) {
    error_report("Invalid header len");
    return -1;
  }
  unsigned data_len = (descriptor->word2 & SPW_TRANSMIT_DESC_DATA_LEN_MASK);
  unsigned tail = (data_len > 0) ? 2 : 1;
  unsigned char* res = (unsigned char*)malloc(RMAP_MIN_PACKAGE_LEN + data_len + tail);
  *package = res;

  cpu_physical_memory_read(descriptor->word1, res, header_len);
	res[RMAP_TRANSACTION_ID_MS_] = (uint8_t)(counter >> 8);
	res[RMAP_TRANSACTION_ID_LS_] = (uint8_t)counter;
	--counter;

  unsigned char header_crc = calculate_crc(res, header_len);
  res += header_len;
  *res = header_crc;
  ++res;

  if (data_len > 0) {
    unsigned char data_crc = calculate_crc(res, data_len);
    res += data_len;
    *res = data_crc;
  }

  ++res;
  *res = RMAP_EOP;

  return RMAP_MIN_PACKAGE_LEN + data_len + tail;
}

static SocketAddress *build_socket_address(const char *bindto, const char *port) {
    SocketAddress *saddr = g_new0(SocketAddress, 1);
    saddr->type = SOCKET_ADDRESS_KIND_INET;
    saddr->u.inet.data = g_new0(InetSocketAddress, 1);
    saddr->u.inet.data->host = g_strdup(bindto);
    saddr->u.inet.data->port = g_strdup(port);

    return saddr;
}

static void connect_to_io_socket(void)
{
  QemuOpts *machine_opts = qemu_get_machine_opts();
  const char *port = qemu_opt_get(machine_opts, "spw-port");
  const char *addr = qemu_opt_get(machine_opts, "spw-addr");
  error_report("port inside spw : %s", port);
  error_report("addr inside spw : %s", addr);

  io_channel = QIO_CHANNEL(qio_channel_socket_new());
  error_report("socket created");

  SocketAddress *connect_addr = build_socket_address(addr, port);

  int connection = qio_channel_socket_connect_sync(QIO_CHANNEL_SOCKET(io_channel), connect_addr, &error_abort);
  if (connection == -1)
    error_report("connection error");
}

static void write_to_io_channel_socket(unsigned char* buf, int len)
{
	log_package(buf, true);
  ssize_t res = qio_channel_write(io_channel, buf, len, &error_abort);
  // error_report("send characters: %lu", res);
  // error_report("send");
}

static uint64_t space_wire_read(void *opaque, hwaddr offset,
                           unsigned size)
{
    SpaceWireState *state = opaque;
    qemu_set_irq(state->irq, 0);
    return 0;
}

void *main_loop(void *arg)
{
  error_report("main_loop()");
  int read_chars = 1;
	bool non_completed = true;
	RMAP_Socket_Read_Status read_status = RMAP_SOCKET_READ_STATUS_START;
  int current_package_len = 0;
	char* buffer = (char*)malloc(RMAP_MAX_PACKAGE_LEN);

	while (read_chars > 0) {
		switch (read_status) {
		case RMAP_SOCKET_READ_STATUS_START:
		{
			error_report("start");
			read_chars = qio_channel_read(io_channel, buffer, RMAP_MIN_PACKAGE_LEN, &error_abort);
			non_completed = true;
			current_package_len = 0;

			if (read_chars < RMAP_MIN_PACKAGE_LEN) {
				read_status = RMAP_SOCKET_READ_STATUS_PARTIAL_HEADER;
			} else {
				log_package(buffer, false);
				if (get_rmap_data_len(buffer) == 0)
          read_status = RMAP_SOCKET_READ_STATUS_READ_EOP;
        else
          read_status = RMAP_SOCKET_READ_STATUS_DATA;
			}
		}
		break;

		case RMAP_SOCKET_READ_STATUS_DATA:
		{
      error_report("data");
			unsigned expected = get_rmap_data_len(buffer) + RMAP_DATA_CRC_LEN;
			error_report("expected: %u", expected);
			read_chars = qio_channel_read(io_channel, buffer + current_package_len, expected, &error_abort);
			error_report("read_chars: %d", read_chars);

			if (read_chars < expected)
				read_status = RMAP_SOCKET_READ_STATUS_PARTIAL_DATA;
			else
				read_status = RMAP_SOCKET_READ_STATUS_READ_EOP;
		}
		break;

		case RMAP_SOCKET_READ_STATUS_PARTIAL_HEADER:
		{
      error_report("partial_header");
			read_chars = qio_channel_read(io_channel, buffer + current_package_len, RMAP_MIN_PACKAGE_LEN - current_package_len, &error_abort);

			if (read_chars + current_package_len == RMAP_MIN_PACKAGE_LEN) {
				log_package(buffer, false);
				read_status = RMAP_SOCKET_READ_STATUS_DATA;
			}
		}
		break;

		case RMAP_SOCKET_READ_STATUS_PARTIAL_DATA:
		{
      error_report("partial_data");
			unsigned expected = RMAP_MIN_PACKAGE_LEN + get_rmap_data_len(buffer) + RMAP_DATA_CRC_LEN - current_package_len;
			error_report("expected: %u", expected);
			read_chars = qio_channel_read(io_channel, buffer + current_package_len, expected, &error_abort);
			error_report("read_chars: %d", read_chars);

			error_report("%d - %d", current_package_len + read_chars, RMAP_MIN_PACKAGE_LEN + get_rmap_data_len(buffer) + RMAP_DATA_CRC_LEN);
			if (current_package_len + read_chars == RMAP_MIN_PACKAGE_LEN + get_rmap_data_len(buffer) + RMAP_DATA_CRC_LEN) {
				read_status = RMAP_SOCKET_READ_STATUS_READ_EOP;
			}
		}
		break;

		case RMAP_SOCKET_READ_STATUS_READ_EOP:
		{
      error_report("eop");
			read_chars = qio_channel_read(io_channel, buffer + current_package_len, 1, &error_abort);
			read_status = RMAP_SOCKET_READ_STATUS_COMPLETED;
		}
		break;

		case RMAP_SOCKET_READ_STATUS_COMPLETED:
		{
      error_report("~~received | len: %d", current_package_len);
			read_status = RMAP_SOCKET_READ_STATUS_START;
			non_completed = false;
		}

		}

		if (non_completed)
      current_package_len += read_chars;

    if (read_chars < 0) {
      error_report("Reading from socket failed");
      break;
    }

    if (read_chars == 0) {
      error_report("Server disconnected");
      break;
    }
	}

  return NULL;
}

void* transmit_loop(void* arg)
{
  while (1) {
    if (!(transmitDescTable[registers.trnsDescIndex].word0 & TRNS_DESCRIPTOR_ENABLE_MASK))
      break;

    int header_len = transmitDescTable[registers.trnsDescIndex].word0 & 0xFF;
    cpu_physical_memory_read(transmitDescTable[registers.trnsDescIndex].word1, &RMAPHeader, header_len * sizeof (uint8_t));

    unsigned char* package = NULL;
    int package_size = create_rmap_package(&transmitDescTable[registers.trnsDescIndex], &package);

    write_to_io_channel_socket(package, package_size);
		free(package);
    transmitDescTable[registers.trnsDescIndex].word0 &= ~TRNS_DESCRIPTOR_ENABLE_MASK;
    registers.trnsDescIndex = (registers.trnsDescIndex + 1) % DESCRIPTOR_TABLE_LEN;
  }

  return NULL;
}

static void space_wire_write(void *opaque, hwaddr offset,
                        uint64_t value, unsigned size)
{
    SpaceWireState *state = opaque;

    switch (offset) {
      case 0x4:
      {
        error_report("rcv, len: %ld", sizeof(receiveDescTable) * DESCRIPTOR_TABLE_LEN);
        cpu_physical_memory_read(value, &receiveDescTable, sizeof(receiveDescTable));
        error_report("rcv2");
        registers.rcvDescIndex = 0;

        break;
      }

      case 0x8:
      {
        // error_report("trns");
        cpu_physical_memory_read(value, &transmitDescTable, sizeof(transmitDescTable));
        registers.trnsDescIndex = 0;
        qemu_thread_create(&transmit_loop_thread, NULL, transmit_loop, NULL, QEMU_THREAD_DETACHED);

        break;
      }
    }
}

static void spacewire_set_irq(void *opaque, int irq, int level)
{
    error_report(">>>  %s", __FUNCTION__);
    SpaceWireState *s = (SpaceWireState *)opaque;

    qemu_set_irq(s->irq, 1);
}

static const MemoryRegionOps space_wire_ops = {
    .read = space_wire_read,
    .write = space_wire_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static const VMStateDescription vmstate_space_wire = {
    .name = "spacewire",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_INT32_ARRAY(level, SpaceWireState, 2),
        VMSTATE_END_OF_LIST()
    }
};

static void space_wire_init(Object *obj)
{
    SpaceWireState *s = SPACEWIRE(obj);
    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);

    memory_region_init_io(&s->iomem, obj, &space_wire_ops, s,
                          "spacewire", 0x12);
    sysbus_init_mmio(sbd, &s->iomem);
    sysbus_init_irq(sbd, &s->irq);
    s->irq = qemu_allocate_irq(spacewire_set_irq, s, 0);

    connect_to_io_socket();
		file = qio_channel_file_new_path("/tmp/spw_test.log", O_WRONLY | O_CREAT | O_APPEND, 0660, &error_abort);
    qemu_thread_create(&main_loop_thread, NULL, main_loop, NULL, QEMU_THREAD_DETACHED);
}

static void space_wire_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *k = DEVICE_CLASS(klass);
    k->vmsd = &vmstate_space_wire;
}

static const TypeInfo space_wire_info = {
    .name          = TYPE_SPACEWIRE,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(SpaceWireState),
    .instance_init = space_wire_init,
    .class_init    = space_wire_class_init,
};

static void spacewire_register_types(void)
{
    type_register_static(&space_wire_info);
}

type_init(spacewire_register_types)
