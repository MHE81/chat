package main;

import java.io.*;
import java.net.Socket;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;


public class ClientManager implements Runnable {
    Socket clientHolder;
    Server serverHolder;
    InputStream fromClientStream;
    OutputStream toClientStream;
    DataInputStream reader;
    DataOutputStream writer;
    ArrayList<ClientManager> players = new ArrayList<>();
    ArrayList<String> fieldsOfGame = new ArrayList<>();
    ArrayList<String> playersNames = new ArrayList<>();
    ClientManager hostOfGame;
    String[][] fieldsConcept;
    int totalRate = 0;
    int currentRate = 0;
    int repeatGameNum = 0;
    boolean timeGame = false;

   public ClientManager(Server server, Socket client) {
        serverHolder = server;
        clientHolder = client;
   }

   public ClientManager() {}

    public void run() {
        try {
            // input stream (stream from client)
            fromClientStream = clientHolder.getInputStream();
            // output stream (stream to client)
            toClientStream = clientHolder.getOutputStream();
            reader = new DataInputStream(fromClientStream);
            writer = new DataOutputStream(toClientStream);
            // send message to client
            while (true) {
                String command = reader.readUTF();
                System.out.println(command);
                if (command.equals("1")) {
                    //new Game button pushed(Host Client)
                    while(true) {
                        String name;
                        int numberOfClients = 0;
                        String letter = "";
                        String newCommand = reader.readUTF();
                        System.out.println(newCommand);

                        if(newCommand.equals("Back"))
                            break;
                        else if (newCommand.equals("Username")) {
                            name = reader.readUTF();
                            System.out.println(name);
                            serverHolder.addClientManager(name, this);
                            serverHolder.hostNames.add(name);
                            players.add(this);
                            playersNames.add(name);
                        }
                        else if(newCommand.equals("Game Details")){
                            clear(fieldsOfGame);
                            letter = reader.readUTF();
                            System.out.println(letter);
                            String n = reader.readUTF();
                            int size = Integer.parseInt(n);
                            System.out.println(size);
                            for(int i = 0; i < size; i++){
                                String field = reader.readUTF();
                                fieldsOfGame.add(field);
                                System.out.println(field);
                            }
                            //read "End"
                            System.out.println(reader.readUTF());
                            serverHolder.addGameController(fieldsOfGame, letter);
                            System.out.println("Done!");
                            writer.writeUTF("Start");
                        }
                        else if(newCommand.equals("Number Of Clients")){
                            numberOfClients = Integer.parseInt(reader.readUTF());
                            System.out.println(numberOfClients);
                            repeatGameNum = Integer.parseInt(reader.readUTF());
                                String str = reader.readUTF();
                                if (str.equals("Time")){
                                    timeGame = true;
                                }
                            //wait for other clients to connect
                            while (players.size() < numberOfClients){
                                System.out.println("1");
                            }
                            writer.writeUTF("Connect!");
                        }
                        else if(newCommand.equals("Get Game Fields")){
                            try {
                                //serverHolder.startEveryOne(this);
                                writer.writeUTF(String.valueOf(fieldsOfGame.size()));
                                for(int i = 0; i < fieldsOfGame.size(); i++){
                                    System.out.println(fieldsOfGame.get(i));
                                    writer.writeUTF(fieldsOfGame.get(i));
                                }
                               //if(numberOfClients == 1){
                                // System.out.println("here");
                                // ClientManager computer = new ClientManager();
                                // computer.fieldsOfGame = fieldsOfGame;
                                // computer.fieldsConcept = setComputerConcepts(fieldsOfGame);
                                // players.add(computer);
                                // playersNames.add("Computer");
                                // for(int i = 0; i < fieldsConcept.length; i++)
                                // System.out.println(fieldsConcept[i][1]);
                                // }
//                             writer.writeUTF("Sleep");
                                if(timeGame)
                                    TimeUnit.SECONDS.sleep(60);
                            }catch (Exception exception){}
                        }
                        else if (newCommand.equals("Fields' Concept")) {
                             //Host Fields
                            writer.writeUTF(String.valueOf(fieldsOfGame.size()));
                            fieldsConcept = new String[fieldsOfGame.size()][2];
                            for(int i = 0; i < fieldsOfGame.size(); i++){
                                writer.writeUTF(fieldsOfGame.get(i));
                                fieldsConcept[i][0] = fieldsOfGame.get(i);
                                fieldsConcept[i][1] = reader.readUTF();
                                System.out.println(fieldsConcept[i][1]);
                            }
                            //serverHolder.stopEveryOne(this);
                        }
                        else if(newCommand.equals("Get Rate")){
                                currentRate += serverHolder.setGameConcepts(fieldsConcept);
                                currentRate -= serverHolder.getRate(players, this);
                                System.out.println(currentRate);
                                writer.writeUTF(String.valueOf(currentRate));
                                clear(fieldsOfGame);
                                totalRate += currentRate;
                                currentRate = 0;
                        }
                        else if(newCommand.equals("Get All Rates")){
                            int[] rate = serverHolder.getPlayersRates(players);
                            writer.writeUTF(String.valueOf(rate.length));
                            for(int i = 0; i < rate.length; i++){
                                writer.writeUTF(playersNames.get(i));
                            }
                            for(int i = 0; i < rate.length; i++){
                                writer.writeUTF(String.valueOf(rate[i]));
                            }
                        }
                    }
                }
                else if (command.equals("2")) {
                    //join to a Game button pushed(Guest Client)
                    while (true){
                        String newCommand = reader.readUTF();
                        System.out.println(newCommand);
                        String name = "";
                        if(newCommand.equals("Back"))
                            break;
                        else if (newCommand.equals("Username")) {
                            //guest client
                            name = reader.readUTF();
                            System.out.println(name);
                            serverHolder.addClientManager(name, this);
                            playersNames.add(name);
                        }
                        else if(newCommand.equals("Get Host Names")){
                            int size = serverHolder.hostNames.size();
                            System.out.println(size);
                            writer.writeUTF(String.valueOf(size));
                            for(int i = 0; i < size; i++){
                                writer.writeUTF(serverHolder.hostNames.get(i));
                            }
                            writer.writeUTF("End");
                        }
                        else if(newCommand.equals("Set Host Name")){
                            String hostName = reader.readUTF();
                            System.out.println(hostName);
                            ClientManager gameHost = serverHolder.findClientManager(hostName);
                            gameHost.players.add(this);
                            setHostName(gameHost);
                            if(hostOfGame.players.size() == players.size())
                                serverHolder.hostNames.remove(hostName);
                            hostOfGame.playersNames.add(playersNames.get(0));
                            repeatGameNum = hostOfGame.repeatGameNum;
                            writer.writeUTF(String.valueOf(repeatGameNum));
                        }
                        else if(newCommand.equals("Get Game Fields")){
                            try {
                                fieldsOfGame = hostOfGame.fieldsOfGame;
                                System.out.println(fieldsOfGame.size());
                                writer.writeUTF(String.valueOf(fieldsOfGame.size()));
                                for(int i = 0; i < fieldsOfGame.size(); i++){
                                    System.out.println(fieldsOfGame.get(i));
                                    writer.writeUTF(fieldsOfGame.get(i));
                                }
                                //writer.writeUTF("Sleep");
                                if(hostOfGame.timeGame) {
                                    writer.writeUTF("Time");
                                    TimeUnit.SECONDS.sleep(60);
                                }
                                else
                                    writer.writeUTF("Normal");
                            }catch (Exception exception){
                                exception.printStackTrace();
                            }
                        }
                        else if (newCommand.equals("Fields' Concept")) {
                            //Guest Fields' Concepts
                            writer.writeUTF(String.valueOf(fieldsOfGame.size()));
                            fieldsConcept = new String[fieldsOfGame.size()][2];
                            for(int i = 0; i < fieldsOfGame.size(); i++){
                                writer.writeUTF(fieldsOfGame.get(i));
                                fieldsConcept[i][0] = fieldsOfGame.get(i);
                                fieldsConcept[i][1] = reader.readUTF();
                                System.out.println(fieldsConcept[i][1]);
                            }
                        }
                        else if(newCommand.equals("Get Rate")){
                            currentRate += serverHolder.setGameConcepts(fieldsConcept);
                            currentRate -= serverHolder.getRate(hostOfGame.players, this);
                            System.out.println(currentRate);
                            writer.writeUTF(String.valueOf(currentRate));
                            clear(fieldsOfGame);
                            totalRate += currentRate;
                            currentRate= 0;
                        }
                        else if(newCommand.equals("Get All Rates")){
                            int[] rate = serverHolder.getPlayersRates(hostOfGame.players);
                            writer.writeUTF(String.valueOf(hostOfGame.playersNames.size()));
                            for(int i = 0; i < hostOfGame.playersNames.size(); i++){
                                writer.writeUTF(hostOfGame.playersNames.get(i));
                            }
                            for(int i = 0; i < rate.length; i++){
                                writer.writeUTF(String.valueOf(rate[i]));
                            }
                        }
                    }
                } else if (command.equals("3")) {
                    //Exit Button Pushed
                    System.out.println("Exit Button Pushed");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public void setHostName(ClientManager hostName){
       hostOfGame = hostName;
    }

    public void clear(ArrayList<String> arrayList) {
        for (int i = 0; i < arrayList.size(); i++)
            arrayList.remove(i);
    }

    public String[][] setComputerConcepts(ArrayList<String> fields) throws Exception {
        String [][] computerConcepts = new String[fields.size()][2];
        for(int i = 0; i < fields.size(); i++){
            computerConcepts[i][0] = fields.get(i);
        }
        while(!reader.readUTF().equals("Fields' Concept")){
            for (int i = 0; i < fields.size(); i++) {
                TimeUnit.SECONDS.sleep(15);
                if (fields.get(i).equals("Firstname")) {
                    computerConcepts[i][1] = serverHolder.gameControl.firstname.setComputerConcept();
                } else if (fields.get(i).equals("Lastname")) {
                    computerConcepts[i][1] = serverHolder.gameControl.lastname.setComputerConcept();
                } else if (fields.get(i).equals("Animal")) {
                    computerConcepts[i][1] = serverHolder.gameControl.animal.setComputerConcept();
                } else if (fields.get(i).equals("Car")) {
                    computerConcepts[i][1] = serverHolder.gameControl.car.setComputerConcept();
                } else if (fields.get(i).equals("City")) {
                    computerConcepts[i][1] = serverHolder.gameControl.city.setComputerConcept();
                } else if (fields.get(i).equals("Clothes")) {
                    computerConcepts[i][1] = serverHolder.gameControl.clothes.setComputerConcept();
                } else if (fields.get(i).equals("Country")) {
                    computerConcepts[i][1] = serverHolder.gameControl.country.setComputerConcept();
                } else if (fields.get(i).equals("Flower")) {
                    computerConcepts[i][1] = serverHolder.gameControl.flower.setComputerConcept();
                } else if (fields.get(i).equals("Food")) {
                    computerConcepts[i][1] = serverHolder.gameControl.food.setComputerConcept();
                } else if (fields.get(i).equals("Fruit")) {
                    computerConcepts[i][1] = serverHolder.gameControl.fruit.setComputerConcept();
                } else if (fields.get(i).equals("Things")) {
                    computerConcepts[i][1] = serverHolder.gameControl.things.setComputerConcept();
                }
            }
        }
        return computerConcepts;
    }
}