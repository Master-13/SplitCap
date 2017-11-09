using System;
using System.Collections.Generic;
using System.Text;
using System.IO;

namespace SplitCap {
    class FramePayloadWriter : PcapFileHandler.IFrameWriter {
        private static Type tcpPacket=typeof(PacketParser.Packets.TcpPacket);
        private static Type udpPacket=typeof(PacketParser.Packets.UdpPacket);
        private static Type rawPacketType=typeof(PacketParser.Packets.RawPacket);
        
        private string filename;
        private System.IO.FileStream fileStream;
        private bool isOpen;
        private Type inputPacketBaseType;



        public FramePayloadWriter(string filename, System.IO.FileMode fileMode, int bufferSize, Type inputPacketBaseType) {
            this.filename=filename;
            this.fileStream=new FileStream(filename, fileMode, FileAccess.Write, FileShare.Write, bufferSize, FileOptions.SequentialScan);
            this.isOpen=true;
            this.inputPacketBaseType = inputPacketBaseType;
        }


        #region IFrameWriter Members
        public bool IsOpen { get { return this.isOpen; } }
        public string Filename { get { return this.filename; } }


        public void Close() {
            this.fileStream.Flush();
            this.fileStream.Close();
            this.isOpen=false;
        }

        public void WriteFrame(PcapFileHandler.PcapFrame frame) {
            WriteFrame(frame, false);
        }

        public void WriteFrame(PcapFileHandler.PcapFrame frame, bool flush) {
            PacketParser.Frame packetParserFrame = new PacketParser.Frame(frame.Timestamp, frame.Data, inputPacketBaseType, 0, false);

            foreach(PacketParser.Packets.AbstractPacket p in packetParserFrame.PacketList) {
                if(p.GetType()==rawPacketType) {
                    return;//this frame isn't worth parsing any more
                }
                else if(p.GetType()==tcpPacket || p.GetType()==udpPacket) {
                    foreach(PacketParser.Packets.AbstractPacket payloadPacket in p.GetSubPackets(false)) {
                        byte[] l7data = payloadPacket.GetPacketData();
                        fileStream.Write(l7data, 0, l7data.Length);
                        break;
                        
                    }
                    if(flush)
                        fileStream.Flush();
                    return;
                }
            }
        }



        #endregion


        public bool OutputIsPcapNg {
            get { throw new NotImplementedException(); }
        }

        public void WriteFrame(byte[] rawFrameHeaderBytes, byte[] rawFrameDataBytes, bool littleEndian) {
            throw new NotImplementedException();
        }

        public void Dispose() {
            throw new NotImplementedException();
        }
    }
}
