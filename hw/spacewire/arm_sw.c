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

#define SPW_FIFO_LENGTH 64
#define RMAP_CONST_PACKET_LEN 18
#define RMAP_PROTOCOL_IDENTIFIER 0x01
#define RMAP_PACKET_TYPE_COMMAND 0x40
#define RMAP_PACKET_WRITE_COMMAND 0x20
#define RMAP_EOP 0

#define SPW_TRANSMIT_DESC_HEADER_MASK 0x000000FF
#define SPW_TRANSMIT_DESC_NONCRC_MASK 0x00000F00
#define SPW_TRANSMIT_DESC_ENABLE_MASK 0x00001000
#define SPW_TRANSMIT_DESC_WRAP_MASK 0x00002000
#define SPW_TRANSMIT_DESC_INTERRUPT_ENABLE_MASK 0x00004000
#define SPW_TRANSMIT_DESC_LINK_ERROR_MASK 0x00008000
#define SPW_TRANSMIT_DESC_APPEND_HEADER_CRC_MASK 0x00010000
#define SPW_TRANSMIT_DESC_APPEND_DATA_CRC_MASK 0x00020000
#define SPW_TRANSMIT_DESC_CRC_TYPE_MASK 0x000C0000
#define SPW_TRANSMIT_DESC_DATA_LEN_MASK 0x00FFFFFF

#define TYPE_SPACEWIRE "spacewire"
#define SPACEWIRE(obj) OBJECT_CHECK(SpaceWireState, (obj), TYPE_SPACEWIRE)

typedef struct SpaceWireState {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    int level[2];
    qemu_irq irq;
} SpaceWireState;

typedef struct _SpWRegisters {
    uint32_t control;
    uint32_t status;
    uint32_t defaultAddress;
    uint32_t clockDivisor;
    uint32_t destinationKey;
    uint32_t timeCode;
    uint32_t reserved[2];
    uint32_t dmaControl;
    uint32_t dmaRxMaxLength;
    uint32_t dmaTransmitDescriptorAddress;
    uint32_t dmaReceiveDescriptorAddress;
    uint32_t dmaAddress;
} SpWRegisters;

typedef struct {
    uint32_t word0;
    uint32_t word1;
    uint32_t word2;
    uint32_t word3;
} SpWTransmitDescriptor;

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

SpWRegisters registers;
static SpWTransmitDescriptor descriptor_list_head;

unsigned char calculate_crc(unsigned char *data, unsigned int len)
{
  unsigned char crc = 0;
  for (unsigned int i = 0; i < len; ++i) {
    crc = RMAP_CRCTable[crc ^ *data];
    data++;
  }

  return crc;
}

unsigned char* create_rmap_packet(SpWTransmitDescriptor *descriptor)
{
  unsigned data_len = descriptor->word2 & SPW_TRANSMIT_DESC_DATA_LEN_MASK;
  unsigned char* packet = (unsigned char*)calloc(1, sizeof(RMAP_CONST_PACKET_LEN + data_len));

  // packet[0] Destination logical address
  packet[1] = RMAP_PROTOCOL_IDENTIFIER;
  packet[2] |= RMAP_PACKET_TYPE_COMMAND;
  packet[2] |= RMAP_PACKET_WRITE_COMMAND;
  packet[3] = registers.destinationKey;
  // packet[4] Same logical dmaAddress

  srand(time(NULL));
  int transaction_identifier = rand() & 0x0000FFFF;
  packet[5] = (transaction_identifier & 0x0000FF00) >> 8;
  packet[6] = transaction_identifier & 0x000000FF;
  // packet[7] Extended write dmaAddress
  // packet[8] .. packet[11] write address
  packet[12] = (data_len & 0x0000FF0000) >> 16;
  packet[13] = (data_len & 0x000000FF00) >> 8;
  packet[14] = data_len & 0x00000000FF;
  packet[15] = calculate_crc(packet, 10);
  // unsigned char *data_ptr = (unsigned char *)descriptor->word3;
  // memcpy(packet + 16, data_ptr, data_len);
  // packet[16 + data_len] = calculate_crc(data_ptr, data_len);
  // packet[16 + data_len + 1] = RMAP_EOP;

  return packet;
}

static void write_package_to_io_channel_file(unsigned char* buf, size_t len)
{
    const char* spw_file_name = "space-wire-tests/4fce092336_space_wire.txt";
    QIOChannel *dst;

    dst = QIO_CHANNEL(qio_channel_file_new_path(
                          spw_file_name,
                          O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644,
                          &error_abort));
    error_report("dst io channel: %s", dst ? "acquired" : "nope");

    struct iovec iov = { .iov_base = buf,
                         .iov_len = len };

    ssize_t res = qio_channel_writev(dst, &iov, 1, &error_abort);

    error_report("saved characters: %lu", res);
}

static SocketAddress *build_socket_address(const char *bindto, const char *port) {
    SocketAddress *saddr;

    saddr = g_new0(SocketAddress, 1);

    InetSocketAddress *inet;
    saddr->type = SOCKET_ADDRESS_KIND_INET;
    inet = saddr->u.inet.data = g_new0(InetSocketAddress, 1);
    inet->host = g_strdup(bindto);
    inet->port = g_strdup(port);

    return saddr;
}

static void write_to_io_channel_socket(void)
{
  QIOChannel *dst = QIO_CHANNEL(qio_channel_socket_new());
  error_report("socket created");

  SocketAddress *connect_addr = build_socket_address("127.0.0.1", "1984");

  int connection = qio_channel_socket_connect_sync(QIO_CHANNEL_SOCKET(dst), connect_addr, &error_abort);
  if (connection == -1)
    error_report("connection error");

  char buf[] = "Wizard is never late";
  struct iovec iov = { .iov_base = buf,
                       .iov_len = 20 };

  ssize_t res = qio_channel_writev(dst, &iov, 1, &error_abort);
  error_report("send characters: %lu", res);
}

static uint64_t space_wire_read(void *opaque, hwaddr offset,
                           unsigned size)
{
    error_report("read: %p", descriptor_list_head);
    // return (uint64_t)descriptor_list_head;
    return 1;
}

static void space_wire_write(void *opaque, hwaddr offset,
                        uint64_t value, unsigned size)
{
    SpaceWireState *state = opaque;
    SpWTransmitDescriptor ptr;
    // cpu_physical_memory_read(value, &ptr, sizeof(SpWTransmitDescriptor));
    error_report("write : %lu", value);
    // error_report("state: %p", state);
    // error_report("offset: %lu", offset);
    // error_report("value: %lu", value);
    // error_report("size: %u", size);
    //
    // error_report("word0 = %u", ptr.word0);
    // error_report("word1 = %u", ptr.word1);
    // error_report("word2 = %u", ptr.word2);
    // error_report("word3 = %u", ptr.word3);
    //
    // unsigned char *buf = create_rmap_packet(&ptr);
    // error_report("crc = %u", buf[15]);

    // write_package_to_io_channel_file(&buf, 10);
    // write_to_io_channel_socket();

    QemuOpts *machine_opts = qemu_get_machine_opts();
    const char *port = qemu_opt_get(machine_opts, "spw-port");
    error_report("port inside spw : %s", port);

    qemu_set_irq(state->irq, value);
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
                          "spacewire", 0x1000);
    sysbus_init_mmio(sbd, &s->iomem);
    sysbus_init_irq(sbd, &s->irq);
    s->irq = qemu_allocate_irq(spacewire_set_irq, s, 0);
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
