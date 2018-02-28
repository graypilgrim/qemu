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
#include "qapi/error.h"

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

SpWRegisters registers;

typedef struct {
    uint32_t word0;
    uint32_t word1;
    uint32_t word2;
    uint32_t word3;
} SpWTransmitDescriptor;

static SpWTransmitDescriptor descriptor_list_head;

unsigned char calculate_crc(unsigned char *data, unsigned int len)
{
  return 0;
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
    cpu_physical_memory_read(value, &ptr, sizeof(SpWTransmitDescriptor));
    error_report("write");
    error_report("state: %p", state);
    error_report("offset: %lu", offset);
    error_report("value: %lu", value);
    error_report("size: %u", size);

    error_report("word0 = %u", ptr.word0);
    error_report("word1 = %u", ptr.word1);
    error_report("word2 = %u", ptr.word2);
    error_report("word3 = %u", ptr.word3);

    unsigned char *buf = create_rmap_packet(&ptr);
    write_package_to_io_channel_file(&buf, 10);
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

    sysbus_init_irq(sbd, &s->irq);
    memory_region_init_io(&s->iomem, obj, &space_wire_ops, s,
                          "spacewire", 0x1000);
    sysbus_init_mmio(sbd, &s->iomem);
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
