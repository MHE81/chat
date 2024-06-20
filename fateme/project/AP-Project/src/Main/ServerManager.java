package Main;

import javafx.application.Platform;
import java.io.DataInputStream;


public class ServerManager implements Runnable{
    DataInputStream readerHolder;
    GameScene clientFXUIHolder;

    public ServerManager(DataInputStream reader, GameScene clientFXUI){
        readerHolder = reader;
        clientFXUIHolder = clientFXUI;
    }

    public void run(){
    }
}
