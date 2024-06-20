package First;

import javafx.event.ActionEvent;

import java.io.DataInputStream;

public class ServerManager implements Runnable{
    DataInputStream readerHolder;
    ClientFXUI clientFXUIHolder;

    public ServerManager(DataInputStream reader, ClientFXUI clientFXUI){
        readerHolder = reader;
        clientFXUIHolder = clientFXUI;
    }
    public void run(){

    }

}
