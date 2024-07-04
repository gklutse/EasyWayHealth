import React, { useState } from 'react';
import { View, Text, TextInput, Button, StyleSheet, Alert } from 'react-native';
import axios from 'axios';

export default function ForgotPasswordScreen({ navigation }) {
    const [email, setEmail] = useState('');

    const handleForgotPassword = async () => {
        try {
            const response = await axios.post('http://192.168.255.139:5000/forgot-password', { email });
            if (response.status === 200) {
                Alert.alert('Password reset link sent to your email.');
                navigation.navigate('Login');
            }
        } catch (error) {
            console.error('Error resetting password:', error.response ? error.response.data : error.message);
            Alert.alert('Error', error.response ? error.response.data.error : error.message);
        }
    };

    return (
        <View style={styles.container}>
            <Text>Forgot Password</Text>
            <TextInput
                placeholder="Email"
                value={email}
                onChangeText={setEmail}
                style={styles.input}
            />
            <Button title="Reset Password" onPress={handleForgotPassword} />
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
