import binascii
import datetime
import serial
import requests
from Cryptodome.Cipher import AES
from enum import Enum
from datetime import timezone


with open("key.txt", "r") as keyfile:
    key = binascii.unhexlify(keyfile.read())


class DataType:
    NullData = 0x00
    Boolean = 0x03
    BitString = 0x04
    DoubleLong = 0x05
    DoubleLongUnsigned = 0x06
    OctetString = 0x09
    VisibleString = 0x0A
    Utf8String = 0x0C
    BinaryCodedDecimal = 0x0D
    Integer = 0x0F
    Long = 0x10
    Unsigned = 0x11
    LongUnsigned = 0x12
    Long64 = 0x14
    Long64Unsigned = 0x15
    Enum = 0x16
    Float32 = 0x17
    Float64 = 0x18
    DateTime = 0x19
    Date = 0x1A
    Time = 0x1B
    Array = 0x01
    Structure = 0x02
    CompactArray = 0x13

class Obis:
    def to_bytes(code):
        return bytes([int(a) for a in code.split(".")])
    Timestamp = to_bytes("0.0.1.0.0.255")
    DeviceId = to_bytes("0.0.96.1.0.255")
    CosemDeviceName = to_bytes("0.0.42.0.0.255")
    VoltageL1 = to_bytes("01.0.32.7.0.255")
    VoltageL2 = to_bytes("01.0.52.7.0.255")
    VoltageL3 = to_bytes("01.0.72.7.0.255")
    CurrentL1 = to_bytes("1.0.31.7.0.255")
    CurrentL2 = to_bytes("1.0.51.7.0.255")
    CurrentL3 = to_bytes("1.0.71.7.0.255")
    RealPowerIn = to_bytes("1.0.1.7.0.255")
    RealPowerOut = to_bytes("1.0.2.7.0.255")
    RealEnergyIn = to_bytes("1.0.1.8.0.255")
    RealEnergyOut = to_bytes("1.0.2.8.0.255")
    ReactiveEnergyIn = to_bytes("1.0.3.8.0.255")
    ReactiveEnergyOut = to_bytes("1.0.4.8.0.255")


if __name__ == '__main__':
    serial = serial.Serial(port='/dev/ttyUSB0', baudrate=2400, parity=serial.PARITY_EVEN, stopbits=serial.STOPBITS_ONE, bytesize=serial.EIGHTBITS, timeout=30)
    #serial = open("kaifa_stream.bin", "rb")

    influx_points = ""
    app_message = b""

    while True:
        frame_start = serial.read(1)
        if len(frame_start) != 1:
            print("timeout reading MBUS frame start byte")
            break

        if frame_start[0] != 0x68:
            print(f"invalid MBUS frame start, byte: 0x{frame_start:x}")
            continue

        header = serial.read(3)
        if len(header) != 3:
            print("timeout reading MBUS L/L/start2 block")
            continue

        mbus_frame_len = header[0]
        if header[1] != mbus_frame_len:
            print(f"MBUS length bytes not consistent")
            continue

        if header[2] != 0x68:
            print(f"invalid MBUS frame start2")
            continue

        frame = serial.read(mbus_frame_len + 2)
        if len(frame) != mbus_frame_len + 2:
            print("timeout reading MBUS frame body")
            continue

        if frame[-1] != 0x16:
            print(f"MBUS frame end byte invalid: 0x{frame[-1]:x}")
            continue

        checksum = sum(frame[:-2]) & 0xff
        if frame[-2] != checksum:
            print(f"MBUS frame checksum mismatch (calc) 0x{checksum:x} != 0x{frame[-1]:x} (recv)")
            continue

        if frame[0] != 0x53:
            print(f"not a long frame, type: 0x{frame[0]:x}")
            continue

        if frame[1] != 0xff:
            print(f"not a broadcast frame, addr: 0x{frame[1]:x}")
            continue

        if frame[2] > 0x1f:
            print(f"MBUS frame with header 0x{frame[2]:x} not supported!")
            continue

        segment_number = frame[2] & 0x0f
        is_last_segment = (frame[2] & 0x10) > 0

        if frame[3] != 0x01:
            print(f"DLMS/COSEM STSAP is not 0x01: 0x{frame[3]:x}")
            continue

        if frame[4] != 0x67:
            print(f"DLMS/COSEM DTSAP is not 0x67: 0x{frame[4]:x}")
            continue

        if segment_number == 0:
            app_message = b""

        app_message += frame[5:-2]

        if is_last_segment:
            if app_message[0] != 0xdb:
                print(f"DLMS/COSEM ciphering service is not 0xDB: 0x{app_message[0]:x}")
                continue

            if app_message[1] != 0x08:
                print(f"DLMS/COSEM system title length is not 8 bytes: 0x{app_message[1]:x}")
                continue

            system_title = app_message[2:10]
            length = app_message[10]
            pos = 11
            if length == 0x81:
                length = app_message[11]
                pos = 12
            elif length == 0x82:
                length = (app_message[11] << 8) + app_message[12]
                pos = 13

            security_suite = app_message[pos] & 0x0f
            is_authenticated = (app_message[pos] & 0x10) > 0
            is_encrypted = (app_message[pos] & 0x20) > 0
            is_broadcast = (app_message[pos] & 0x40) > 0
            is_compressed = (app_message[pos] & 0x80) > 0
            frame_counter = app_message[pos+1:pos+5]

            payload = app_message[pos+5:pos+5+length]
            if len(payload) != length-5:
                print(f"DLMS/COSEM payload length (actual) {len(payload)} != {length-5} (should)")
                continue

            #fc = int.from_bytes(frame_counter, "big")
            #print(f"DLMS/COSEM payload {len(payload)} bytes, suite {security_suite}, auth: {is_authenticated}, encr: {is_encrypted}, bc: {is_broadcast}, compr: {is_compressed}, frame: {fc}")
            #print(payload)
            
            iv = system_title + frame_counter
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            decrypted = cipher.decrypt(payload)

            #print("\nDecrypted:")
            #print(decrypted.hex())

            pos = 20
            total = len(decrypted)
            obis = {}
            while pos < total:
                if decrypted[pos] != DataType.OctetString:
                    print(f"Unsupported OBIS header type {decrypted[pos]}")
                    break
                if decrypted[pos + 1] != 6:
                    print(f"Unsupported OBIS code length {decrypted[pos + 1]}")
                    break
                obis_code = decrypted[pos + 2 : pos + 2 + 6]
                data_type = decrypted[pos + 2 + 6]
                pos += 2 + 6 + 1

                #print(f"OBIS code {obis_code} DataType {data_type}")
                if data_type == DataType.DoubleLongUnsigned:
                    value = int.from_bytes(decrypted[pos : pos + 4], "big")
                    scale = decrypted[pos + 4 + 3]
                    if scale > 128: scale -= 256
                    pos += 4 + 8
                    obis[obis_code] = value*(10**scale)
                    #print(f"DLU: {value}, {scale}, {value*(10**scale)}")
                elif data_type == DataType.LongUnsigned:
                    value = int.from_bytes(decrypted[pos : pos + 2], "big")
                    scale = decrypted[pos + 2 + 3]
                    if scale > 128: scale -= 256
                    pos += 2 + 8
                    obis[obis_code] = value*(10**scale)
                    #print(f"LU: {value}, {scale}, {value*(10**scale)}")
                elif data_type == DataType.OctetString:
                    octet_len = decrypted[pos]
                    octet = decrypted[pos + 1 : pos + 1 + octet_len]
                    pos += 1 + octet_len + 2
                    obis[obis_code] = octet
                    #print(f"OCTET: {octet_len}, {octet}")

            timestamp = obis[Obis.Timestamp]
            year = int.from_bytes(timestamp[:2], "big")
            month = timestamp[2]
            day = timestamp[3]
            hour = timestamp[5]
            minute = timestamp[6]
            second = timestamp[7]
            millisec = timestamp[8]
            offset_min = int.from_bytes(timestamp[9:11], "big", signed=True)
            timezone = datetime.timezone(datetime.timedelta(minutes=-offset_min))
            dtobj = datetime.datetime(year, month, day, hour, minute, second, millisec*1000, tzinfo=timezone)
            milli_ts = int(dtobj.timestamp() * 1000)
            #print(dtobj)
            
            if True:
                print(dtobj)
                #print(f"Device: " + obis[Obis.DeviceId].decode("ascii"))
                print(f"Phase 1:    {obis[Obis.CurrentL1]: >6.2f}A at {obis[Obis.VoltageL1]: >5.1f}V")
                print(f"Phase 2:    {obis[Obis.CurrentL2]: >6.2f}A at {obis[Obis.VoltageL2]: >5.1f}V")
                print(f"Phase 3:    {obis[Obis.CurrentL3]: >6.2f}A at {obis[Obis.VoltageL3]: >5.1f}V")
                print(f"Power In: {obis[Obis.RealPowerIn]/1000: >9.3f}kW     Power Out:  {obis[Obis.RealPowerOut]/1000: >9.3f}kW")
                print(f"Energy In:{obis[Obis.RealEnergyIn]/1000: >9.3f}kWh    Energy Out: {obis[Obis.RealEnergyOut]/1000: >9.3f}kWh")
                print(f"Inductive:{obis[Obis.ReactiveEnergyIn]/1000: >9.3f}kVAh   Capacitive: {obis[Obis.ReactiveEnergyOut]/1000: >9.3f}kVAh")
                print()

            influx = f"energy,meter=eg power_in={obis[Obis.RealPowerIn]/1000},power_out={obis[Obis.RealPowerOut]/1000},energy_in={obis[Obis.RealEnergyIn]/1000},energy_out={obis[Obis.RealEnergyOut]/1000},energy_inductive={obis[Obis.ReactiveEnergyIn]/1000},energy_capacitive={obis[Obis.ReactiveEnergyOut]/1000},current1={obis[Obis.CurrentL1]},current2={obis[Obis.CurrentL2]},current3={obis[Obis.CurrentL3]},voltage1={obis[Obis.VoltageL1]},voltage2={obis[Obis.VoltageL2]},voltage3={obis[Obis.VoltageL3]} {milli_ts}"
            #print(influx)
            requests.post("http://localhost:8086/write?db=Energy&precision=ms", data=influx.encode("ascii"))
            #influx_points += influx + "\n"
    #requests.post("http://localhost:8086/write?db=Energy&precision=ms", data=influx_points.encode("ascii"))
    
