/*
        Tor Research Framework - easy to use tor client library/framework
        Copyright (C) 2014  Dr Gareth Owen <drgowen@gmail.com>
        www.ghowen.me / github.com/drgowen/tor-research-framework

        This program is free software: you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation, either version 3 of the License, or
        (at your option) any later version.

        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public License
        along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
package tor;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import tor.util.TorCircuitException;
import tor.util.TorDocumentParser;

import javax.management.Descriptor;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.TreeMap;

/**
 * Created by gho on 25/07/14.
 */
public class HiddenService {
    final static Logger log = LogManager.getLogger();

    // onion as base32 encoded, replica=[0,1],
    public static byte[] getDescId(String onion, byte replica) {
        byte[] onionbin = new Base32().decode(onion.toUpperCase());
        assert onionbin.length == 10;

        long curtime = System.currentTimeMillis() / 1000L;
        int oid = onionbin[0] & 0xff;

        long t = (curtime + (oid * 86400L / 256)) / 86400L;

        ByteBuffer buf = ByteBuffer.allocate(10);
        buf.putInt((int) t);
        buf.put(replica);
        buf.flip();

        MessageDigest md = TorCrypto.getSHA1();
        md.update(buf);
        byte hashT[] = md.digest();

        md = TorCrypto.getSHA1();
        return md.digest(ArrayUtils.addAll(onionbin, hashT)); //md.digest();
    }

    public static OnionRouter[] findResposibleDirectories(String onionb32) {
        Consensus con = Consensus.getConsensus();

        // get list of nodes with HS dir flag
        TreeMap<String, OnionRouter> routers = con.getORsWithFlag("HSDir");
        Object keys[] = routers.keySet().toArray();
        Object vals[] = routers.values().toArray();

        ArrayList<OnionRouter> rts = new ArrayList<>();

        for (int replica = 0; replica < 2; replica++) {
            // Get nodes just to right of HS's descID in the DHT
            int idx = -Arrays.binarySearch(keys, Hex.encodeHexString(getDescId(onionb32, (byte) replica)));

            for (int i = 0; i < 3; i++) {
                rts.add((OnionRouter) vals[(idx + i) % vals.length]);
            }
        }

        // return list containing hopefully six ORs.
        return rts.toArray(new OnionRouter[0]);
    }

    // blocking
    public static String fetchHSDescriptor(TorSocket sock, final String onion) throws IOException {
        // get list of ORs with resposibility for this HS
        OnionRouter ors[] = findResposibleDirectories(onion);
        // loop through responsible directories until successful
        for (int i = 0; i < ors.length; i++) {
            OnionRouter or = ors[i];
            log.debug("Trying Directory Server: {}", or);

            // establish circuit to responsible director
            TorCircuit circ = sock.createCircuit(true);
            try {
                circ.create();
                circ.extend(ors[0]);
            } catch(TorCircuitException e) {
                log.error("HS fetched failed due to circuit failure - moving to next directory");
                continue;
            }

            final int replica = i < 3 ? 0 : 1;

            // asynchronous call
            TorStream st = circ.createDirStream(new TorStream.TorStreamListener() {
                @Override
                public void dataArrived(TorStream s) {
                }

                @Override
                public void connected(TorStream s) {
                    try {
                        s.sendHTTPGETRequest("/tor/rendezvous2/" + new Base32().encodeAsString(HiddenService.getDescId(onion, (byte) replica)), "dirreq");
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }

                @Override
                public void disconnected(TorStream s) {
                    synchronized (onion) {
                        onion.notify();
                    }
                }

                @Override
                public void failure(TorStream s) {
                    synchronized (onion) {
                        onion.notify();
                    }
                }
            });

            // wait for notification from the above listener that data is here! (that remote side ended connection - data could be blank
            synchronized (onion) {
                try {
                    onion.wait(1000);
                    if(circ.state== TorCircuit.STATES.DESTROYED) {
                        System.out.println("HS - Desc Fetch - Circuit Destroyed");
                        throw new TorCircuitException("circuit destroyed");
                    }
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            // get HTTP response and body
            String data = IOUtils.toString(st.getInputStream());
            circ.destroy();

            // HTTP success code
            if (data.length() < 1 || !data.split(" ")[1].equals("200")) {
                continue;
            }

            int dataIndex = data.indexOf("\r\n\r\n");
            return data.substring(dataIndex);
        }

        log.warn("Not found hs descriptor!");
        return null;
    }

    public static String getHSDescriptor(TorSocket sock, final String descriptor_id, final String fprint) throws IOException {
        return HSDescriptorRequest(sock, descriptor_id, fprint, null);
    }

    public static String postHSDescriptor(TorSocket sock, final String descriptor, final String fprint) throws IOException {
        return HSDescriptorRequest(sock, null, fprint, descriptor);
    }

    public static String HSDescriptorRequest(TorSocket sock, final String descriptor_id, final String fprint, final String descriptor) throws IOException {
        // Send GET and POST requests to specified HSDir.

        Consensus con = Consensus.getConsensus();
        OnionRouter or = null;
        // Try get the requested OR from the consensus
        if (con.routers.containsKey(fprint)){
            or = con.routers.get(fprint);
        } else {
            log.error("Could not find the request HSDir in the consensus");
            throw new IOException("Could not find the requested HSDir in the consensus. Check the fingerprint is correct");
        }

        log.debug("Trying Directory Server: {}", or);

        // establish circuit to responsible directory
        TorCircuit circ = sock.createCircuit(true);
        try {
            circ.create();
            circ.extend(or);
        } catch(TorCircuitException e) {
            throw new IOException("HS Fetch failed due to circuit failure, you should retry.");
        }

        // asynchronous call
        TorStream st = circ.createDirStream(new TorStream.TorStreamListener() {
            @Override
            public void dataArrived(TorStream s) {
            }

            @Override
            public void connected(TorStream s) {
                try {
                    if(descriptor != null && !descriptor.isEmpty()) {
                        s.sendHTTPPOSTRequest("/tor/rendezvous2/publish", "dirreq", descriptor);
                    } else {
                        s.sendHTTPGETRequest("/tor/rendezvous2/" + descriptor_id, "dirreq");
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

            @Override
            public void disconnected(TorStream s) {
                synchronized (fprint) {
                    fprint.notify();
                }
            }

            @Override
            public void failure(TorStream s) {
                synchronized (fprint) {
                    fprint.notify();
                }
            }
        });

        // wait for notification from the above listener that data is here! (that remote side ended connection - data could be blank
        synchronized (fprint) {
            try {
                fprint.wait(1000);
                if(circ.state== TorCircuit.STATES.DESTROYED) {
                    System.out.println("HS - Desc Fetch - Circuit Destroyed");
                    throw new TorCircuitException("circuit destroyed");
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
                throw new IOException("Circuit failed");
            }
        }

        // get HTTP response and body
        String data = IOUtils.toString(st.getInputStream());
        circ.destroy();

        // HTTP success code
        if (data.length() < 1 || !data.split(" ")[1].equals("200")) {
            throw new IOException("HTTPError: "+ data); // Throw the error
        }

        int dataIndex = data.indexOf("\r\n\r\n");
        return data.substring(dataIndex);
    }

    public static void sendIntroduce(TorSocket sock, String onion, TorCircuit rendz) throws IOException {
        log.debug("Fetching Hidden Service Descriptor");
        String hsdescTxt = fetchHSDescriptor(sock, onion);
        OnionRouter rendzOR = rendz.getLastHop().router;


        // parse the hidden service descriptor
        TorDocumentParser hsdesc = new TorDocumentParser(hsdescTxt);
        //decode the intro points
        String intopointsb64 = new String(Base64.decode(hsdesc.map.get("introduction-points")));
        // parse intro points document
        TorDocumentParser intros = new TorDocumentParser(intopointsb64);
        // get first intro point
        String introPointIdentities[] = intros.getArrayItem("introduction-point");

        int introPointNum = 0;

        String ip0 = Hex.encodeHexString(new Base32().decode(introPointIdentities[introPointNum].toUpperCase()));
        OnionRouter ip0or = Consensus.getConsensus().routers.get(ip0);
        byte[] serviceKey = Base64.decode(intros.getArrayItem("service-key")[introPointNum]);
        byte skHash[] = TorCrypto.getSHA1().digest(serviceKey);
        assert (skHash.length == 20);
        log.debug("Using Intro Point: {}, building circuit...", ip0or);

        TorCircuit ipcirc = sock.createCircuit(true);
        ipcirc.create();
        ipcirc.extend(ip0or);

        // outer packet
        ByteBuffer buf = ByteBuffer.allocate(1024);
        buf.put(skHash); // service PKhash

        // inner handshake
        ByteBuffer handshake = ByteBuffer.allocate(1024);
        handshake.put((byte) 2); //ver
        handshake.put(rendzOR.ip.getAddress());  // rendz IP addr
        handshake.putShort((short) rendzOR.orport);
        try {
            handshake.put(new Hex().decode(rendzOR.identityhash.getBytes()));
        } catch (DecoderException e) {
            e.printStackTrace();
        }
        handshake.putShort((short) rendzOR.onionKeyRaw.length);  // rendz key len
        handshake.put(rendzOR.onionKeyRaw); // rendz key
        handshake.put(rendz.rendezvousCookie);  //rend cookie

        // tap handshake / create handshake
        byte priv_x[] = new byte[128];
        TorCrypto.rnd.nextBytes(priv_x);   // g^x
        rendz.temp_x = TorCrypto.byteToBN(priv_x);
        rendz.temp_r = null;

        BigInteger pubKey = TorCrypto.DH_G.modPow(rendz.temp_x, TorCrypto.DH_P);
        byte pubKeyByte[] = TorCrypto.BNtoByte(pubKey);
        handshake.put(pubKeyByte);

        handshake.flip();

        // convert to byte array
        byte handshakeBytes[] = new byte[handshake.remaining()];
        handshake.get(handshakeBytes);

        // encrypt handshake
        PublicKey skPK = TorCrypto.asn1GetPublicKey(serviceKey);
        buf.put(TorCrypto.hybridEncrypt(handshakeBytes, skPK));

        buf.flip();
        byte introcell[] = new byte[buf.remaining()];
        buf.get(introcell);

        ipcirc.send(introcell, TorCircuit.RELAY_COMMAND_INTRODUCE1, false, (short) 0);
        log.debug("waiting for introduce acknowledgement");
        ipcirc.waitForState(TorCircuit.STATES.INTRODUCED, false);

        log.debug("Now waiting for rendezvous connect");
        rendz.waitForState(TorCircuit.STATES.RENDEZVOUS_COMPLETE, false);

        ipcirc.destroy(); // no longer needed
        log.debug("Hidden Service circuit built");
    }
}
