package main;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.concurrent.TimeUnit;

public class Server {
    ServerSocket mServer;
    int serverPort = 9090;
    ArrayList<Thread> threads = new ArrayList<Thread>();
    HashMap<String, ClientManager> clientsMap = new HashMap<String, ClientManager>();
    GameControl gameControl = new GameControl();
    ArrayList<String> hostNames = new ArrayList<>();
    public Server() {
        try {
            // create server socket!
            mServer = new ServerSocket(serverPort);
            System.out.println("Server Created!");
            // always running
            while (true) {
                // wait for client
                Socket client = mServer.accept();
                System.out.println("Connected to New Client!");
                Thread t = new Thread(new ClientManager(this, client));
                // add Thread to "threads" list
                threads.add(t);
                // start thread
                t.start();
            }
        } catch (IOException e) {}
    }
    public void addClientManager(String clientName,ClientManager cm){
        clientsMap.put(clientName, cm);
    }

    public ClientManager findClientManager(String clientName){
        return clientsMap.get(clientName);
    }

    public void addGameController(ArrayList<String> fields, String letter){
        gameControl.setGameControl(fields, letter);
    }
    public int setGameConcepts(String[][] fieldsOfGame){
        int rate = gameControl.setConcepts(fieldsOfGame);
        return rate;
    }
    public int getRate(ArrayList<ClientManager> nameOfPlayers, ClientManager me){
        int count = 0;
        boolean find = false;
        for(int i = 0; i < me.fieldsConcept.length; i++){
            for(int j = 0; j < nameOfPlayers.size() && !find ; j++){
                if(!nameOfPlayers.get(j).equals(me)) {
                    String[][] sbConcept = nameOfPlayers.get(j).fieldsConcept;
                    if(me.fieldsConcept[i][1] == null || sbConcept[i][1] == null)
                        continue;
                    else if (sbConcept[i][1].equals(me.fieldsConcept[i][1])) {
                        count++;
                        find = true;
                    }
                }
                else
                    continue;
            }
        }
        return count * 5;
    }
    public int[] getPlayersRates(ArrayList<ClientManager> nameOfPlayers){
        int[] playersRates = new int[nameOfPlayers.size()];
        for(int i = 0; i < nameOfPlayers.size(); i++){
            playersRates[i] = nameOfPlayers.get(i).totalRate;
        }
        return playersRates;
    }
    public void stopEveryOne(ClientManager hostClient){
        try {
            for (int i = 1; i < hostClient.players.size(); i++)
                hostClient.players.get(i).writer.writeUTF("Stop");
        }catch (Exception exception){
            exception.printStackTrace();
        }
    }
    public void startEveryOne(ClientManager hostClient){
        try {
            for (int i = 1; i < hostClient.players.size(); i++)
                hostClient.players.get(i).writer.writeUTF("Start");
        }catch (Exception exception){
            exception.printStackTrace();
        }
    }
    public static void main(String[] args) {
        Server server = new Server();
    }
}