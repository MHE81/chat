package Main;

import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.stage.Stage;

public class ShowRatings extends GameScene{

    @FXML
    private Label ratinglbl;

    @FXML
    private Button continueBttn;

    @FXML
    private Button exitGameBttn;


    public void setRatings(){
            try {
                client.writer.writeUTF("Get Rate");
                String rate = client.reader.readUTF();
                System.out.println(rate);
                //client.totalRate += Integer.parseInt(rate);
                ratinglbl.setText(rate);
                client.gameDoneNum++;
            }catch (Exception exception){}
    }
    public void exitGameButtonPushed(ActionEvent event){
        try {
            //client.reader.readUTF();
            Parent allRatesParent = FXMLLoader.load(getClass().getResource("LastScene.fxml"));
            Scene allRatesScene = new Scene(allRatesParent);
            //this line gets the stage information
            Stage window = (Stage) ((Node) event.getSource()).getScene().getWindow();
            window.setScene(allRatesScene);
            window.show();
        }catch (Exception exception){}
    }
    public void continueButtonPushed(ActionEvent event){
        try {
            Parent guestGameParent = FXMLLoader.load(getClass().getResource("ShowGuestGame.fxml"));
            Scene guestGameScene = new Scene(guestGameParent);
            //this line gets the stage information
            Stage window = (Stage) ((Node) event.getSource()).getScene().getWindow();
            window.setScene(guestGameScene);
            window.show();
        }catch (Exception exception){}
    }

    @FXML
    public void initialize(){
        if(client.gameDoneNum == client.gameRepeatNum - 1){
            exitGameBttn.setDisable(false);
            continueBttn.setDisable(true);
        }
    }
}
