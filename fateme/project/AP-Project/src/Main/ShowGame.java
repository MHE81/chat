package Main;

import javafx.animation.KeyFrame;
import javafx.animation.Timeline;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.stage.Stage;
import javafx.util.Duration;

public class ShowGame extends GameScene{

    @FXML
    private TextField firstnameTxt;

    @FXML
    private TextField lastnameTxt;

    @FXML
    private TextField animalTxt;

    @FXML
    private TextField carTxt;

    @FXML
    private TextField cityTxt;

    @FXML
    private TextField clothesTxt;

    @FXML
    private TextField countryTxt;

    @FXML
    private TextField flowerTxt;

    @FXML
    private TextField foodTxt;

    @FXML
    private TextField fruitTxt;

    @FXML
    private TextField thingsTxt;

    @FXML
    private Button submitBttn;

    @FXML
    private Button stopBttn;

    @FXML
    private Label timeLbl;

    int second;

    @FXML
    public void startButtonPushed(){
        try {
            if(client.timeGame){
                submitBttn.setDisable(true);
                second = 60;
                timer();
            }
            client.writer.writeUTF("Get Game Fields");
            int size = Integer.parseInt(client.reader.readUTF());
            for(int i = 0; i < size; i++){
                String field = client.reader.readUTF();
                if(field.equals("Firstname"))
                    firstnameTxt.setDisable(false);
                else if(field.equals("Lastname"))
                    lastnameTxt.setDisable(false);
                else if(field.equals("Animal"))
                    animalTxt.setDisable(false);
                else if(field.equals("Car"))
                    carTxt.setDisable(false);
                else if(field.equals("City"))
                    cityTxt.setDisable(false);
                else if(field.equals("Clothes"))
                    clothesTxt.setDisable(false);
                else if(field.equals("Country"))
                    countryTxt.setDisable(false);
                else if(field.equals("Flower"))
                    flowerTxt.setDisable(false);
                else if(field.equals("Food"))
                    foodTxt.setDisable(false);
                else if(field.equals("Fruit"))
                    fruitTxt.setDisable(false);
                else if(field.equals("Things"))
                    thingsTxt.setDisable(false);
            }
        }catch (Exception exception){}
    }
    @FXML
    public void submitButtonPushed(){
        try {
            client.writer.writeUTF("Fields' Concept");
            int size = Integer.parseInt(client.reader.readUTF());
            for(int i = 0; i < size; i++) {
                String field = client.reader.readUTF();
                if(field.equals("Firstname")) {
                    String str = firstnameTxt.getText();
                    if(str.equals(null))
                        client.writer.writeUTF("null");
                    else
                        client.writer.writeUTF(str);
                }
                else if(field.equals("Lastname")) {
                    String str = lastnameTxt.getText();
                    if(str.equals(null))
                        client.writer.writeUTF("null");
                    else
                        client.writer.writeUTF(str);
                }
                else if(field.equals("Animal")) {
                    String str = animalTxt.getText();
                    if(str.equals(null))
                        client.writer.writeUTF("null");
                    else
                        client.writer.writeUTF(str);
                }
                else if(field.equals("Car")){
                    String str = carTxt.getText();
                    if(str.equals(null))
                        client.writer.writeUTF("null");
                    else
                        client.writer.writeUTF(str);
                }
                else if(field.equals("City")){
                    String str = cityTxt.getText();
                    if(str.equals(null))
                        client.writer.writeUTF("null");
                    else
                        client.writer.writeUTF(str);
                }
                else if(field.equals("Clothes")){
                    String str = clothesTxt.getText();
                    if(str.equals(null))
                        client.writer.writeUTF("null");
                    else
                        client.writer.writeUTF(str);
                }
                else if(field.equals("Country")) {
                    String str = countryTxt.getText();
                    if(str.equals(null))
                        client.writer.writeUTF("null");
                    else
                        client.writer.writeUTF(str);
                }
                else if(field.equals("Flower")){
                    String str = flowerTxt.getText();
                    if(str.equals(null))
                        client.writer.writeUTF("null");
                    else
                        client.writer.writeUTF(str);
                }
                else if(field.equals("Food")){
                    String str = foodTxt.getText();
                    if(str.equals(null))
                        client.writer.writeUTF("null");
                    else
                        client.writer.writeUTF(str);
                }
                else if(field.equals("Fruit")){
                    String str = fruitTxt.getText();
                    if(str.equals(null))
                        client.writer.writeUTF("null");
                    else
                        client.writer.writeUTF(str);
                }
                else if(field.equals("Things")){
                    String str = thingsTxt.getText();
                    if(str.equals(null))
                        client.writer.writeUTF("null");
                    else
                        client.writer.writeUTF(str);
                }
            }
        }catch(Exception exception){
            exception.printStackTrace();
        }
    }
    public void stopButtonPushed(){
        EventHandler<ActionEvent> event = e -> {
            try {
                    Parent ratingParent = FXMLLoader.load(getClass().getResource("ShowHostRatings.fxml"));
                    Scene ratingScene = new Scene(ratingParent);
                    //this line gets the stage information
                    Stage window = (Stage) ((Node) e.getSource()).getScene().getWindow();
                    window.setScene(ratingScene);
                    window.show();
            }catch (Exception exception){}
        };
        stopBttn.setOnAction(event);
    }
    public void timer(){
        timeLbl.setDisable(false);
        Timeline time = new Timeline();
        time.setCycleCount(Timeline.INDEFINITE);
        KeyFrame frame = new KeyFrame(Duration.seconds(1), new EventHandler<ActionEvent>(){
            @Override
            public void handle(ActionEvent event){
                second--;
                timeLbl.setText("" + second);
                if(second <= 0) {
                    submitBttn.setDisable(false);
                    time.stop();
                }
            }
        });
        time.getKeyFrames().add(frame);
        time.playFromStart();
    }
}