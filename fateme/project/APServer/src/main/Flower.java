package main;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Random;
import java.util.Scanner;

public class Flower{
    private String concept;
    private String path = "C:\\Users\\Fatima\\IdeaProjects\\APServer\\src\\main\\flower.txt";
    private boolean isInGame = false;
    private String mainLetter;

    public Flower(String l){
        mainLetter = l;
        concept = null;
    }
    public boolean search(){
        try {
            File file = new File(path);
            Scanner read = new Scanner(file);
            String str;
            while(read.hasNext()){
                str = read.nextLine();
                if(concept.equals(str))
                    return true;
            }
        }catch(IOException e){
            e.printStackTrace();
        }
        return false;
    }
    public boolean isNameAccepted(){
        if(isInGame) {
            if (concept.startsWith(mainLetter) && search())
                return true;
        }
        return false;
    }
    public void setConcept(String txt){
        concept = txt;
    }
    public void setInGame(){
        isInGame = true;
    }
    public boolean getInGame(){
        return isInGame;
    }
    public String setComputerConcept(){
        ArrayList<String> names = new ArrayList<>();
        try {
            File file = new File(path);
            Scanner read = new Scanner(file);
            String str;
            while(read.hasNext()){
                str = read.nextLine();
                if(str.startsWith(mainLetter))
                    names.add(str);
            }
        }catch(IOException e){
            e.printStackTrace();
        }
        Random random = new Random();
        int num = random.nextInt(names.size());
        return names.get(num);
    }
}
