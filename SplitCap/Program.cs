/**
 * SplitCap is created as part of the Statistical Protocol IDentification
 * research project carried out by Erik Hjelmvik with fundings from .SE.
 * 
 * .SE, a.k.a. The Internet Infrastructure Foundation, is responsible for
 * the top-level Swedish Internets domain, .se. The core business is the
 * registration of domain names and the administration and technical
 * operation of the national domain name registry, at the same time as .SE
 * promotes the positive development of the Internet in Sweden.
 * 
 * More info on .SE is available at:
 * http://www.iis.se/en/
 * 
 * The SplitCap project is available at:
 * http://sourceforge.net/projects/splitcap/
 * 
 * The Statistical Protocol IDentification (SPID) project is available at:
 * http://sourceforge.net/projects/spid/
 * 
 */

using System;
using System.Collections.Generic;
using System.Text;

namespace SplitCap {
    class Program {

        enum SplitMode { Flow, Host, HostPair, Session, NoSplit, Seconds, Packets };
        enum FileType { pcap, L7 };

        delegate int PercentReadDelegate();

        private static Type rawPacketType=typeof(PacketParser.Packets.RawPacket);
        private static Type ipv4Type=typeof(PacketParser.Packets.IPv4Packet);
        private static Type ipv6Type=typeof(PacketParser.Packets.IPv6Packet);
        private static Type tcpPacket=typeof(PacketParser.Packets.TcpPacket);
        private static Type udpPacket=typeof(PacketParser.Packets.UdpPacket);
        private static PacketParser.PopularityList<string, PcapFileHandler.IFrameWriter> pcapWriters;

        //32000 sessions and a 8000 byte file buffer for each session requires 244MB RAM plus overhead
        private const int DEFAULT_PARALLEL_SESSIONS = 10000;
        private const int DEFAULT_FILE_BUFFER_SIZE = 10000;
        private static readonly DateTime EPOCH = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        static void Main(string[] args) {
            
            if(args.Length<1) {
                PrintUsage(Console.Error);
                return;
            }
            //bool ignoreTransportLayer=false;
            SplitMode splitMode = SplitMode.Session;
            int splitArgument = -1;
            FileType outputFileType = FileType.pcap;
            string pcapFilename=null;
            string outputDirectory=null;
            bool deletePreviousOutput=false;
            bool lazyFileCreator = false;
            int parallelSessions = DEFAULT_PARALLEL_SESSIONS;
            int fileBufferSize = DEFAULT_FILE_BUFFER_SIZE;
            Dictionary<System.Net.IPAddress, System.Net.IPAddress> ipFilter = new Dictionary<System.Net.IPAddress, System.Net.IPAddress>();
            Dictionary<ushort, ushort> portFilter = new Dictionary<ushort, ushort>();
            bool recursiveFileSearch = false;

            try {
                for(int i=0; i<args.Length; i++) {
                    //Console.Error.WriteLine("" + args.Length);
                    //Console.Error.WriteLine("" + args[i]);

                    if(args[i].Equals("-r", StringComparison.InvariantCultureIgnoreCase)) {
                        pcapFilename = args[++i];
                    }
                    else if(args[i].Equals("-o", StringComparison.InvariantCultureIgnoreCase)) {
                        outputDirectory = args[++i];
                    }
                    else if(args[i].Equals("-d", StringComparison.InvariantCultureIgnoreCase)) {
                        deletePreviousOutput = true;
                    }
                    else if(args[i].Equals("-p", StringComparison.InvariantCultureIgnoreCase)) {
                        parallelSessions = Int32.Parse(args[++i]);
                    }
                    else if(args[i].Equals("-b", StringComparison.InvariantCultureIgnoreCase)) {
                        fileBufferSize = Int32.Parse(args[++i]);
                    }
                    else if(args[i].Equals("-s", StringComparison.InvariantCultureIgnoreCase)) {
                        string group = args[++i];
                        if(group.Equals("flow", StringComparison.InvariantCultureIgnoreCase))
                            splitMode = SplitMode.Flow;
                        else if(group.Equals("host", StringComparison.InvariantCultureIgnoreCase))
                            splitMode = SplitMode.Host;
                        else if(group.Equals("hostpair", StringComparison.InvariantCultureIgnoreCase))
                            splitMode = SplitMode.HostPair;
                        else if(group.Equals("session", StringComparison.InvariantCultureIgnoreCase))
                            splitMode = SplitMode.Session;
                        else if (group.Equals("nosplit", StringComparison.InvariantCultureIgnoreCase))
                            splitMode = SplitMode.NoSplit;
                        else if (group.Equals("seconds", StringComparison.InvariantCultureIgnoreCase)) {
                            splitMode = SplitMode.Seconds;
                            splitArgument = Int32.Parse(args[++i]);
                        }
                        else if (group.Equals("packets", StringComparison.InvariantCultureIgnoreCase)) {
                            splitMode = SplitMode.Packets;
                            splitArgument = Int32.Parse(args[++i]);
                        }
                    }
                    else if (args[i].Equals("-ip", StringComparison.InvariantCultureIgnoreCase)) {
                        string ip = args[++i];
                        System.Net.IPAddress ipAddress;
                        if (System.Net.IPAddress.TryParse(ip, out ipAddress))
                            ipFilter.Add(ipAddress, ipAddress);
                    }
                    else if (args[i].Equals("-port", StringComparison.InvariantCultureIgnoreCase)) {
                        string port = args[++i];
                        ushort portNumber;
                        if (ushort.TryParse(port, out portNumber))
                            portFilter.Add(portNumber, portNumber);
                    }
                    else if (args[i].Equals("-y", StringComparison.InvariantCultureIgnoreCase)) {
                        string ftype = args[++i];
                        if (ftype.Equals("L7", StringComparison.InvariantCultureIgnoreCase))
                            outputFileType = FileType.L7;
                        else if (ftype.Equals("pcap", StringComparison.InvariantCultureIgnoreCase))
                            outputFileType = FileType.pcap;
                    }
                    else if (args[i].Equals("-z", StringComparison.InvariantCultureIgnoreCase)) {
                        lazyFileCreator = true;
                    }
                    else if (args[i].Equals("-recursive", StringComparison.InvariantCultureIgnoreCase)) {
                        recursiveFileSearch = true;
                    }
                    else if (args.Length == 1 && args[i] != null && (args[i].Contains("cap") || args[i].Contains("dmp")) && System.IO.File.Exists(args[i])) {
                        //if user drag-and-drops a file onto the SplitCap.exe file
                        pcapFilename = args[i];
                    }
                    else {
                        Console.Error.WriteLine("Unknown argument : " + args[i]);
                        PrintUsage(Console.Error);
                        return;
                    }
                }
            }
            catch {
                PrintUsage(Console.Error);
                return;
            }
            if(recursiveFileSearch && !System.IO.Directory.Exists(pcapFilename)) {
                Console.Error.WriteLine("Input directory does not exist");
                PrintUsage(Console.Error);
                return;
            }
            else if (!recursiveFileSearch && !System.IO.File.Exists(pcapFilename) && pcapFilename.Trim() != "-") {
                Console.Error.WriteLine("Input file does not exist");
                PrintUsage(Console.Error);
                return;
            }
            if (recursiveFileSearch) {
                System.IO.DirectoryInfo di = new System.IO.DirectoryInfo(pcapFilename);
                foreach(System.IO.FileInfo fi in GetPcapFilesRecursively(di))
                    Split(fi.FullName, splitMode, splitArgument, lazyFileCreator, outputDirectory, parallelSessions, fileBufferSize, outputFileType, deletePreviousOutput, ipFilter, portFilter);
            }
            else {
                Split(pcapFilename, splitMode, splitArgument, lazyFileCreator, outputDirectory, parallelSessions, fileBufferSize, outputFileType, deletePreviousOutput, ipFilter, portFilter);
            }
        }

        private static IEnumerable<System.IO.FileInfo> GetPcapFilesRecursively(System.IO.DirectoryInfo di) {
            foreach (System.IO.FileInfo pcapFileInfo in di.GetFiles("*.*cap")) {
                yield return pcapFileInfo;
            }
            foreach (System.IO.DirectoryInfo subDirectoryInfo in di.GetDirectories()) {
                foreach (System.IO.FileInfo fi in GetPcapFilesRecursively(subDirectoryInfo))
                    yield return fi;
            }
        }

        private static void Split(string pcapFilename, SplitMode splitMode, int splitArgument, bool lazyFileCreator, string outputDirectory, int parallelSessions, int fileBufferSize, FileType outputFileType, bool deletePreviousOutput, Dictionary<System.Net.IPAddress, System.Net.IPAddress> ipFilter, Dictionary<ushort, ushort> portFilter) {
            if (pcapFilename.Trim() == "-") {
                //read from stdin
                using (System.IO.Stream stdin = System.Console.OpenStandardInput()) {
                    using (PcapFileHandler.PcapStreamReader observationReader = new PcapFileHandler.PcapStreamReader(stdin)) {
                        Split(observationReader, "SplitCap", splitMode, splitArgument, outputDirectory, parallelSessions, fileBufferSize, outputFileType, deletePreviousOutput, ipFilter, portFilter);
                    }
                }
                
            }
            else if (!lazyFileCreator || SplitNeeded(pcapFilename, splitMode, splitArgument)) {
                using (PcapFileHandler.PcapFileReader observationReader = new PcapFileHandler.PcapFileReader(pcapFilename, 4000, null)) {
                    /*
                    if (outputDirectory == null) {
                        outputDirectory = GetFilename(observationReader.Filename);

                        if (outputDirectory.Contains("."))
                            outputDirectory = outputDirectory.Substring(0, outputDirectory.LastIndexOf('.'));
                    }
                    //remove the outputDirectory in case it exists
                    if (deletePreviousOutput && System.IO.Directory.Exists(outputDirectory)) {
                        Console.Out.WriteLine("Removing previous files in output directory " + outputDirectory.ToString());
                        System.IO.Directory.Delete(outputDirectory, true);
                    }
                    if (!System.IO.Directory.Exists(outputDirectory))
                        System.IO.Directory.CreateDirectory(outputDirectory);
                    ParsePcapStream(observationReader, outputDirectory, parallelSessions, fileBufferSize, splitMode, splitArgument, outputFileType, ipFilter, portFilter);
                     * */
                    Split(observationReader, observationReader.Filename, splitMode, splitArgument, outputDirectory, parallelSessions, fileBufferSize, outputFileType, deletePreviousOutput, ipFilter, portFilter);
                }
            }
        }

        private static void Split(PcapFileHandler.PcapStreamReader observationReader, string pcapFilename, SplitMode splitMode, int splitArgument, string outputDirectory, int parallelSessions, int fileBufferSize, FileType outputFileType, bool deletePreviousOutput, Dictionary<System.Net.IPAddress, System.Net.IPAddress> ipFilter, Dictionary<ushort, ushort> portFilter) {
            if (outputDirectory == null) {
                outputDirectory = GetFilename(pcapFilename);

                if (outputDirectory.Contains("."))
                    outputDirectory = outputDirectory.Substring(0, outputDirectory.LastIndexOf('.'));
            }
            //remove the outputDirectory in case it exists
            if (deletePreviousOutput && System.IO.Directory.Exists(outputDirectory)) {
                Console.Out.WriteLine("Removing previous files in output directory " + outputDirectory.ToString());
                System.IO.Directory.Delete(outputDirectory, true);
            }
            if (!System.IO.Directory.Exists(outputDirectory))
                System.IO.Directory.CreateDirectory(outputDirectory);
            ParsePcapStream(observationReader, outputDirectory, parallelSessions, fileBufferSize, splitMode, splitArgument, outputFileType, ipFilter, portFilter);
        }


        private static String GetFilename(String filePathAndName) {
            if(filePathAndName.Contains(System.IO.Path.DirectorySeparatorChar.ToString()) && filePathAndName.LastIndexOf(System.IO.Path.DirectorySeparatorChar)+1<filePathAndName.Length)
                return filePathAndName.Substring(filePathAndName.LastIndexOf(System.IO.Path.DirectorySeparatorChar)+1);
            else
                return filePathAndName;
        }

        private static bool SplitNeeded(string pcapFilename, SplitMode splitMode, int splitArgument) {
            using (PcapFileHandler.PcapFileReader observationReader = new PcapFileHandler.PcapFileReader(pcapFilename, 4000, null)) {
                Type packetBaseType = GetPacketBaseType(observationReader.FileDataLinkType[0]);
                string uniqueGroupString = null;
                int frameNumber = 0;
                foreach (PcapFileHandler.PcapFrame packet in observationReader.PacketEnumerator()) {
                    foreach (string groupString in GetGroupStrings(new PacketParser.Frame(packet.Timestamp, packet.Data, packetBaseType, frameNumber++, false, true), splitMode, splitArgument, null, null)) {
                        if (uniqueGroupString == null)
                            uniqueGroupString = groupString;
                        else if (uniqueGroupString != groupString)
                            return true;
                    }
                }
            }
            return false;
        }

        private static Type GetPacketBaseType(PcapFileHandler.PcapFrame.DataLinkTypeEnum dataLinkType) {
            if (dataLinkType == PcapFileHandler.PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_ETHERNET)
                return typeof(PacketParser.Packets.Ethernet2Packet);
            else if (dataLinkType == PcapFileHandler.PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_RAW_IP || dataLinkType == PcapFileHandler.PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_RAW_IP_2 || dataLinkType == PcapFileHandler.PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_RAW_IP_3)
                return typeof(PacketParser.Packets.IPv4Packet);
            else if (dataLinkType == PcapFileHandler.PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_IEEE_802_11)
                return typeof(PacketParser.Packets.IEEE_802_11Packet);
            else if (dataLinkType == PcapFileHandler.PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_IEEE_802_11_WLAN_RADIOTAP)
                return typeof(PacketParser.Packets.IEEE_802_11RadiotapPacket);
            else if (dataLinkType == PcapFileHandler.PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_CHDLC)
                return typeof(PacketParser.Packets.CiscoHdlcPacket);
            else if (dataLinkType == PcapFileHandler.PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_SLL)
                return typeof(PacketParser.Packets.LinuxCookedCapture);
            else if (dataLinkType == PcapFileHandler.PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_NULL)
                return typeof(PacketParser.Packets.NullLoopbackPacket);
            else {
                Console.Error.WriteLine("No packet type found for " + dataLinkType.ToString());
                throw new Exception("No packet type found for " + dataLinkType.ToString());
            }
        }
        

        //private static void ParsePcapFile(PcapFileHandler.PcapFileReader observationReader, string outputDirectory, int parallelSessions, int fileBufferSize, SplitMode splitMode, int splitArgument, FileType outputFileType, IDictionary<System.Net.IPAddress, System.Net.IPAddress> ipFilter, IDictionary<ushort, ushort> portFilter) {
        private static void ParsePcapStream(PcapFileHandler.PcapStreamReader observationReader, string outputDirectory, int parallelSessions, int fileBufferSize, SplitMode splitMode, int splitArgument, FileType outputFileType, IDictionary<System.Net.IPAddress, System.Net.IPAddress> ipFilter, IDictionary<ushort, ushort> portFilter) {

            Type packetBaseType = GetPacketBaseType(observationReader.FileDataLinkType[0]);
            /*
            if(observationReader.FileDataLinkType[0]==PcapFileHandler.PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_ETHERNET)
                packetBaseType=typeof(PacketParser.Packets.Ethernet2Packet);
            else if (observationReader.FileDataLinkType[0] == PcapFileHandler.PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_RAW_IP || observationReader.FileDataLinkType[0] == PcapFileHandler.PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_RAW_IP_2 || observationReader.FileDataLinkType[0] == PcapFileHandler.PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_RAW_IP_3)
                packetBaseType=typeof(PacketParser.Packets.IPv4Packet);
            else if (observationReader.FileDataLinkType[0] == PcapFileHandler.PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_IEEE_802_11)
                packetBaseType=typeof(PacketParser.Packets.IEEE_802_11Packet);
            else if (observationReader.FileDataLinkType[0] == PcapFileHandler.PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_IEEE_802_11_WLAN_RADIOTAP)
                packetBaseType=typeof(PacketParser.Packets.IEEE_802_11RadiotapPacket);
            else if (observationReader.FileDataLinkType[0] == PcapFileHandler.PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_CHDLC)
                packetBaseType=typeof(PacketParser.Packets.CiscoHdlcPacket);
            else if (observationReader.FileDataLinkType[0] == PcapFileHandler.PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_SLL)
                packetBaseType = typeof(PacketParser.Packets.LinuxCookedCapture);
            else if (observationReader.FileDataLinkType[0] == PcapFileHandler.PcapFrame.DataLinkTypeEnum.WTAP_ENCAP_NULL)
                packetBaseType = typeof(PacketParser.Packets.NullLoopbackPacket);
            else{
                Console.Error.WriteLine("No packet type found for "+observationReader.FileDataLinkType.ToString());
                throw new Exception("No packet type found for "+observationReader.FileDataLinkType.ToString());
            }
            */
            String filename = "SplitCap";
            PercentReadDelegate pr = null;

            if (observationReader is PcapFileHandler.PcapFileReader) {
                PcapFileHandler.PcapFileReader fileReader = (PcapFileHandler.PcapFileReader)observationReader;
                filename = GetFilename(fileReader.Filename);
                pr = delegate() { return fileReader.PercentRead; };
            }
            pcapWriters=new PacketParser.PopularityList<string, PcapFileHandler.IFrameWriter>(parallelSessions);
            pcapWriters.PopularityLost+=new PacketParser.PopularityList<string, PcapFileHandler.IFrameWriter>.PopularityLostEventHandler(pcapWriters_PopularityLost);
            Console.CancelKeyPress+=new ConsoleCancelEventHandler(Console_CancelKeyPress);

            //System.Collections.Generic.SortedList<string, PcapFileHandler.PcapFileWriter> pcapWriters=new SortedList<string,PcapFileHandler.PcapFileWriter>();
            Console.Out.WriteLine("Splitting pcap file into seperate pcap files...");
            int percentRead=0;
            int framesRead = 0;
            foreach(PcapFileHandler.PcapFrame packet in observationReader.PacketEnumerator()) {
                
                //if(observationReader.PercentRead>percentRead) {
                if(pr!=null && pr()>percentRead) {
                    //percentRead=observationReader.PercentRead;
                    percentRead = pr();
                    try {
                        Console.CursorLeft = 0;
                    }
                    catch (System.IO.IOException) {
                        //do nothing
                    }
                    Console.Write(percentRead.ToString()+"%");
                    Console.Out.Flush();
                }
                foreach(string groupString in GetGroupStrings(new PacketParser.Frame(packet.Timestamp, packet.Data, packetBaseType, framesRead++, false, true), splitMode, splitArgument, ipFilter, portFilter)) {
                    //string fiveTupleString=GetFiveTupleStrings(new PacketParser.Frame(packet.Timestamp, packet.Data, packetBaseType, 0, false), ignoreTransportLayer);
                    if(groupString!=null) {//see if we've got a session
                        if(!pcapWriters.ContainsKey(groupString)) {
                            try {
                                if (outputFileType == FileType.pcap)
                                    pcapWriters.Add(groupString, new PcapFileHandler.PcapFileWriter(outputDirectory + System.IO.Path.DirectorySeparatorChar + filename + "." + groupString + ".pcap", observationReader.FileDataLinkType[0], System.IO.FileMode.Append, fileBufferSize));
                                else if (outputFileType == FileType.L7)
                                    pcapWriters.Add(groupString, new FramePayloadWriter(outputDirectory + System.IO.Path.DirectorySeparatorChar + filename + "." + groupString + ".bin", System.IO.FileMode.Append, fileBufferSize, packetBaseType));
                                else
                                    throw new Exception("SplitCap cannot handle specified output file type");
                            }
                            catch (System.IO.IOException ioException) {
                                int parallelWriters = pcapWriters.Count;
                                if (parallelWriters > 100) {
                                    Console.Out.WriteLine("\nError creating new output file!");
                                    Console.Out.WriteLine("\nSplitCap does currently have " + parallelWriters + " file handles open in parallel.");
                                    Console.Out.WriteLine("\nTry limiting the number of parallel file handles with the -p switch");
                                    Console.Out.WriteLine("\nFor example: \"SplitCap -r dumpfile.pcap -p " + (parallelWriters - 1) + "\"\n");
                                    Console.Out.Flush();
                                }
                                throw ioException;//re-throw the exception
                            }
                        }
                        pcapWriters[groupString].WriteFrame(packet, false);
                    }
                }
            }
            Console.Out.WriteLine("\nPlease wait while closing all file handles...");
            //close all writers
            foreach(PcapFileHandler.IFrameWriter pcapWriter in pcapWriters.GetValueEnumerator())
                pcapWriter.Close();
        
        }

        private static void PrintUsage(System.IO.TextWriter output) {
            // 80 characters: 00000000011111111112222222222333333333344444444445555555555666666666677777777778
            // 80 characters: 12345678901234567890123456789012345678901234567890123456789012345678901234567890
            output.WriteLine("Usage: SplitCap [OPTIONS]...");
            output.WriteLine("");
            output.WriteLine("OPTIONS:");
            output.WriteLine("-r <input_file> : Set the pcap file to read from.");
            output.WriteLine("                  Use \"-r -\" to read from stdin");
            output.WriteLine("-o <output_directory> : Manually specify output directory");
            output.WriteLine("-d : Delete previous output data");
            output.WriteLine("-p <nr_parallel_sessions> : Set the number of parallel sessions to keep in");
            output.WriteLine("   memory (default = "+DEFAULT_PARALLEL_SESSIONS+"). More sessions might be needed to split pcap");
            output.WriteLine("   files from busy links such as an Internet backbone link, this will however");
            output.WriteLine("   require more memory");
            output.WriteLine("-b <file_buffer_bytes> : Set the number of bytes to buffer for each");
            output.WriteLine("   session/output file (default = "+DEFAULT_FILE_BUFFER_SIZE+"). Larger buffers will speed up the");
            output.WriteLine("   process due to fewer disk write operations, but will occupy more memory.");
            output.WriteLine("-s <GROUP> : Split traffic and group packets to pcap files based on <GROUP>");
            output.WriteLine("   Possible values for <GROUP> are:");
            output.WriteLine("             flow        : Flow, i.e. unidirectional traffic for each 5-tuple,");
            output.WriteLine("                           is grouped together");
            output.WriteLine("             host        : Traffic grouped to one file per host. Most packets");
            output.WriteLine("                           will end up in two files.");
            output.WriteLine("             hostpair    : Traffic grouped based on host-pairs communicating");
            output.WriteLine("             nosplit     : Do not split traffic. Only create ONE output pcap.");
            output.WriteLine("   (default) session     : Packets for each session (bi-directional flow) are");
            output.WriteLine("                           grouped");
            output.WriteLine("             seconds <s> : Split on time, new file after <s> seconds.");
            output.WriteLine("             packets <c> : Split on packet count, new file after <c> packets.");
            output.WriteLine("-ip <IP address to filter on>");
            output.WriteLine("-port <port number to filter on>");
            output.WriteLine("-y <FILETYPE> : Output file type for extracted data. Possible values");
            output.WriteLine("   for <FILETYPE> are:");
            output.WriteLine("             L7   : Only store application layer data");
            output.WriteLine("   (default) pcap : Store complete pcap frames");
            output.WriteLine("-z : Lazy file creation, i.e. only split if needed");
            output.WriteLine("-recursive : Search pcap files in sub-directories recursively");
            output.WriteLine("");
            output.WriteLine("Example 1: SplitCap -r dumpfile.pcap");
            output.WriteLine("Example 2: SplitCap -r dumpfile.pcap -o session_directory");
            output.WriteLine("Example 3: SplitCap -r dumpfile.pcap -s hostpair");
            output.WriteLine("Example 4: SplitCap -r dumpfile.pcap -s flow -y L7");
            output.WriteLine("Example 5: SplitCap -r dumpfile.pcap -s seconds 3600");
            output.WriteLine("Example 6: SplitCap -r dumpfile.pcap -ip 1.2.3.4 -port 80 -port 443 -s nosplit");
            output.WriteLine("Example 7: SplitCap -r C:\\pcaps\\ -recursive -s host -port 53 -o DNS_dir");
            output.WriteLine("Example 8: tcpdump -n -s0 -U -i eth0 -w - | mono SplitCap.exe -r -");
            
        }

        static void Console_CancelKeyPress(object sender, ConsoleCancelEventArgs e) {
            //close all writers
            foreach(PcapFileHandler.IFrameWriter pcapWriter in pcapWriters.GetValueEnumerator())
                try {
                    pcapWriter.Close();
                }
                catch {
                    Console.Error.WriteLine("Error closing file "+pcapWriter.Filename);
                }
            
        }

        static void pcapWriters_PopularityLost(string key, PcapFileHandler.IFrameWriter writer) {
            writer.Close();//flushes and closes the fileStream
        }

        private static IEnumerable<string> GetGroupStrings(PacketParser.Frame frame, SplitMode splitMode, int splitArgument, IDictionary<System.Net.IPAddress, System.Net.IPAddress> ipFilter, IDictionary<ushort, ushort> portFilter) {


            string transportProtocol = null;
            ushort? sourcePort = null;
            ushort? destinationPort = null;
            System.Net.IPAddress sourceIp = null;
            System.Net.IPAddress destinationIp = null;

            foreach (PacketParser.Packets.AbstractPacket p in frame.PacketList) {
                if (p.GetType() == rawPacketType) {
                    break;//this frame isn't worth parsing any more
                }
                else if (p.GetType() == ipv4Type) {
                    sourceIp = ((PacketParser.Packets.IPv4Packet)p).SourceIPAddress;
                    destinationIp = ((PacketParser.Packets.IPv4Packet)p).DestinationIPAddress;
                    if ((portFilter == null || portFilter.Count == 0) && (splitMode == SplitMode.NoSplit || splitMode == SplitMode.Host || splitMode == SplitMode.HostPair))
                        break;
                }
                else if (p.GetType() == ipv6Type) {
                    sourceIp = ((PacketParser.Packets.IPv6Packet)p).SourceIPAddress;
                    destinationIp = ((PacketParser.Packets.IPv6Packet)p).DestinationIPAddress;
                    if ((portFilter == null || portFilter.Count == 0) && (splitMode == SplitMode.NoSplit || splitMode == SplitMode.Host || splitMode == SplitMode.HostPair))
                        break;
                }
                else if (p.GetType() == tcpPacket) {
                    sourcePort = ((PacketParser.Packets.TcpPacket)p).SourcePort;
                    destinationPort = ((PacketParser.Packets.TcpPacket)p).DestinationPort;
                    transportProtocol = "TCP";
                    //there is no point in enumarating further than the TCP packet
                    break;
                }
                else if (p.GetType() == udpPacket) {
                    sourcePort = ((PacketParser.Packets.UdpPacket)p).SourcePort;
                    destinationPort = ((PacketParser.Packets.UdpPacket)p).DestinationPort;
                    transportProtocol = "UDP";
                    //there is no point in enumarating further than the UDP packet
                    break;
                }
            }
            if (splitMode != SplitMode.Packets && splitMode != SplitMode.Session && (sourceIp == null || destinationIp == null))
                yield break;
            else if (splitMode == SplitMode.Session && (transportProtocol == null || sourcePort == null || sourceIp == null))
                yield break;//no session data found...
            else if (ipFilter != null && ipFilter.Count > 0 && !ipFilter.ContainsKey(sourceIp) && !ipFilter.ContainsKey(destinationIp))
                yield break;
            else if (portFilter != null && portFilter.Count > 0) {
                //one of the ports must match the filter!
                if (!sourcePort.HasValue || !destinationPort.HasValue)
                    yield break;
                else if (!portFilter.ContainsKey(sourcePort.Value) && !portFilter.ContainsKey(destinationPort.Value))
                    yield break;
            }
            


            if (splitMode == SplitMode.Host) {
                yield return "Host_" + GetIpString(sourceIp);
                yield return "Host_" + GetIpString(destinationIp);
            }
            else if (splitMode == SplitMode.HostPair) {
                //set the lowest IP first
                if (IsLowToHigh(sourceIp, 0, destinationIp, 0))
                    yield return "HostPair_" + GetIpString(sourceIp) + "_" + GetIpString(destinationIp);
                else
                    yield return "HostPair_" + GetIpString(destinationIp) + "_" + GetIpString(sourceIp);

            }
            else if (splitMode == SplitMode.Flow) {
                //A directional flow, same as session string when IsLowToHigh()==true
                yield return transportProtocol + "_" + GetIpString(sourceIp) + "_" + sourcePort.ToString() + "_" + GetIpString(destinationIp) + "_" + destinationPort.ToString();
            }
            else if (splitMode == SplitMode.NoSplit) {
                yield return "NoSplit";
            }
            else if (splitMode == SplitMode.Packets) {
                yield return "Packets_" + (frame.FrameNumber / splitArgument);
            }
            else if (splitMode == SplitMode.Seconds) {
                long seconds = frame.Timestamp.Subtract(EPOCH).Ticks / 10000000;
                yield return "Seconds_" + ((seconds / splitArgument) * splitArgument);
            }
            else {
                //splitMode == SplitMode.Session
                if (IsLowToHigh(sourceIp, sourcePort.Value, destinationIp, destinationPort.Value))
                    yield return transportProtocol + "_" + GetIpString(sourceIp) + "_" + sourcePort.ToString() + "_" + GetIpString(destinationIp) + "_" + destinationPort.ToString();
                else
                    yield return transportProtocol + "_" + GetIpString(destinationIp) + "_" + destinationPort.ToString() + "_" + GetIpString(sourceIp) + "_" + sourcePort.ToString();
            }

        }

        private static string GetIpString(System.Net.IPAddress ip) {
            return ip.ToString().Replace('.', '-').Replace(':', '-');
        }

        private static bool IsLowToHigh(System.Net.IPAddress sourceIp, ushort sourcePort, System.Net.IPAddress destinationIp, ushort destinationPort) {
            //compare the IP first
            byte[] sb=sourceIp.GetAddressBytes();
            byte[] db=destinationIp.GetAddressBytes();
            for(int i=0; i<sb.Length && i<db.Length; i++)
                if(sb[i]<db[i])
                    return true;
                else if(sb[i]>db[i])
                    return false;
            //now check the ports
            return sourcePort<=destinationPort;
        }
    }
}
