package Main;

import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;

public class Client {
    public Socket mySocket;
    public int port = 9090;
    public String serverAddress = "127.0.0.1";
    public InputStream fromServer;
    public OutputStream toServer;
    public DataInputStream reader;
    public DataOutputStream writer;
    public GameScene clientUIHolder = null;
    public int gameRepeatNum;
    public int gameDoneNum;
    public boolean timeGame = false;

    public Client(GameScene clientUI){
        clientUIHolder = clientUI;
    }
    public Client(){}

    public void start(){
        try {
            mySocket = new Socket(serverAddress, port);
            System.out.println("Connect to Server...");
            fromServer = mySocket.getInputStream();
            toServer = mySocket.getOutputStream();
            reader = new DataInputStream(fromServer);
            writer = new DataOutputStream(toServer);
            Thread t = new Thread(new ServerManager(reader, clientUIHolder));
            t.start();
        } catch (UnknownHostException e){
        } catch (IOException e){
            System.out.println(e.getMessage());
        }

    }
    public static void main(String[] args) {
        new Client().start();
    }
}
