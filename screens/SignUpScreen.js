import React, { useState } from 'react';
import { View, Text, TextInput, Button, StyleSheet, } from 'react-native';
import axios from 'axios';
import { Picker } from '@react-native-picker/picker';

export default function SignUpScreen({ navigation }) {
    const [name, setName] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [role, setRole] = useState('Patient');

    const handleSignup = async () => {
        if (password !== confirmPassword) {
            alert("Passwords do not match");
            return;
        }
        try {
            const response = await axios.post('http://192.168.255.139:5000/signup', { name, email, password, role });
            if (response.status === 201) {
                navigation.navigate('Login');
            }
        } catch (error) {
            console.error('Error signing up:', error);
        }
    };

    return (
        <View style={styles.container}>
            <Text>Sign Up</Text>
            <TextInput
                placeholder="Name"
                value={name}
                onChangeText={setName}
                style={styles.input}
            />
            <TextInput
                placeholder="Email"
                value={email}
                onChangeText={setEmail}
                style={styles.input}
            />
            <TextInput
                placeholder="Password"
                value={password}
                onChangeText={setPassword}
                secureTextEntry
                style={styles.input}
            />
            <TextInput
                placeholder="Confirm Password"
                value={confirmPassword}
                onChangeText={setConfirmPassword}
                secureTextEntry
                style={styles.input}
            />
            <Picker
                selectedValue={role}
                style={styles.input}
                onValueChange={(itemValue) => setRole(itemValue)}
            >
                <Picker.Item label="Patient" value="Patient" />
                <Picker.Item label="Ambulance personnel" value="Ambulance personnel" />
            </Picker>
            <Button title="Sign Up" onPress={handleSignup} />
        </View>
    );
}

const styles = StyleSheet.create({
    container: {
        flex: 1,
        justifyContent: 'center',
        alignItems: 'center',
    },
    input: {
        width: '80%',
        height: 40,
        borderColor: 'gray',
        borderWidth: 1,
        marginBottom: 12,
        paddingHorizontal: 8,
    },
});
